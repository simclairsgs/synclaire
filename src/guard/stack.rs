use std::{collections::HashSet, net::IpAddr, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Instant};

use parking_lot::RwLock;

use crate::{guard::{Guard, GuardContext, GuardDecision, GuardEvent, GuardEventKind, GuardObserver}, SynError};

#[derive(Clone, Default)]
pub struct Allowlist {
    ips: Arc<RwLock<HashSet<IpAddr>>>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&self, ip: IpAddr) {
        self.ips.write().insert(ip);
    }

    pub fn remove(&self, ip: &IpAddr) -> bool {
        self.ips.write().remove(ip)
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.read().contains(ip)
    }

    pub fn clear(&self) {
        self.ips.write().clear();
    }

    pub fn list(&self) -> Vec<IpAddr> {
        self.ips.read().iter().copied().collect()
    }
}

struct GuardStackInner {
    guards: Vec<Arc<dyn Guard>>,
    observer: Option<Arc<dyn GuardObserver>>,
    allowlist: Allowlist,
}

impl GuardStackInner {
    fn emit(&self, event: GuardEvent) {
        if let Some(observer) = &self.observer {
            observer.on_event(event);
        }
    }
}

#[derive(Clone)]
pub struct GuardStack {
    inner: Arc<GuardStackInner>,
}

impl Default for GuardStack {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardStack {
    pub fn builder() -> GuardStackBuilder {
        GuardStackBuilder::default()
    }

    pub fn new() -> Self {
        Self {
            inner: Arc::new(GuardStackInner {
                guards: Vec::new(),
                observer: None,
                allowlist: Allowlist::new(),
            }),
        }
    }

    pub fn allowlist(&self) -> &Allowlist {
        &self.inner.allowlist
    }

    pub fn reserve(&self, context: GuardContext) -> Result<GuardSession, SynError> {
        if self.inner.allowlist.contains(&context.peer_ip) {
            return Ok(GuardSession {
                inner: Arc::clone(&self.inner),
                context,
                closed: AtomicBool::new(false),
                established: AtomicBool::new(false),
                allowed: true,
            });
        }

        for (accepted, guard) in self.inner.guards.iter().enumerate() {
            if let Err(err) = guard.on_reserve(&context) {
                // Roll back: call on_close on guards [0..accepted) in reverse.
                for rollback in self.inner.guards[..accepted].iter().rev() {
                    rollback.on_close(&context);
                }
                let reason = err.to_string();
                self.inner.emit(GuardEvent {
                    guard: guard.name(),
                    kind: GuardEventKind::Reserve,
                    peer_addr: context.peer_addr,
                    decision: GuardDecision::Deny(SynError::guard_rejected(guard.name(), reason.clone())),
                    detail: format!("{} rejected reservation", guard.name()),
                    occurred_at: Instant::now(),
                });
                return Err(SynError::guard_rejected(guard.name(), reason));
            }
            self.inner.emit(GuardEvent {
                guard: guard.name(),
                kind: GuardEventKind::Reserve,
                peer_addr: context.peer_addr,
                decision: GuardDecision::Allow,
                detail: format!("{} allowed reservation", guard.name()),
                occurred_at: Instant::now(),
            });
        }

        Ok(GuardSession {
            inner: Arc::clone(&self.inner),
            context,
            closed: AtomicBool::new(false),
            established: AtomicBool::new(false),
            allowed: false,
        })
    }
}

pub struct GuardSession {
    inner: Arc<GuardStackInner>,
    context: GuardContext,
    closed: AtomicBool,
    established: AtomicBool,
    allowed: bool,
}

impl GuardSession {
    pub fn mark_established(&self) -> Result<(), SynError> {
        if self.allowed || self.established.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        for guard in &self.inner.guards {
            guard.on_established(&self.context)?;
            self.inner.emit(GuardEvent {
                guard: guard.name(),
                kind: GuardEventKind::Established,
                peer_addr: self.context.peer_addr,
                decision: GuardDecision::Allow,
                detail: format!("{} saw connection established", guard.name()),
                occurred_at: Instant::now(),
            });
        }

        Ok(())
    }

    pub fn record_payload(&self, payload: &[u8]) -> Result<(), SynError> {
        if self.allowed {
            return Ok(());
        }

        for guard in &self.inner.guards {
            guard.on_activity(&self.context)?;
            guard.on_payload(&self.context, payload)?;
            self.inner.emit(GuardEvent {
                guard: guard.name(),
                kind: GuardEventKind::Payload,
                peer_addr: self.context.peer_addr,
                decision: GuardDecision::Allow,
                detail: format!("{} inspected {} payload bytes", guard.name(), payload.len()),
                occurred_at: Instant::now(),
            });
        }

        Ok(())
    }

    pub fn touch(&self) -> Result<(), SynError> {
        if self.allowed {
            return Ok(());
        }

        for guard in &self.inner.guards {
            guard.on_activity(&self.context)?;
            self.inner.emit(GuardEvent {
                guard: guard.name(),
                kind: GuardEventKind::Activity,
                peer_addr: self.context.peer_addr,
                decision: GuardDecision::Allow,
                detail: format!("{} saw connection activity", guard.name()),
                occurred_at: Instant::now(),
            });
        }

        Ok(())
    }

    pub fn close(&self) {
        if self.allowed || self.closed.swap(true, Ordering::SeqCst) {
            return;
        }

        for guard in &self.inner.guards {
            guard.on_close(&self.context);
            self.inner.emit(GuardEvent {
                guard: guard.name(),
                kind: GuardEventKind::Close,
                peer_addr: self.context.peer_addr,
                decision: GuardDecision::Allow,
                detail: format!("{} saw connection close", guard.name()),
                occurred_at: Instant::now(),
            });
        }
    }
}

impl Drop for GuardSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Default)]
pub struct GuardStackBuilder {
    guards: Vec<Arc<dyn Guard>>,
    observer: Option<Arc<dyn GuardObserver>>,
    allowlist: Allowlist,
}

impl GuardStackBuilder {
    pub fn push<G>(mut self, guard: G) -> Self
    where
        G: Guard + 'static,
    {
        self.guards.push(Arc::new(guard));
        self
    }

    pub fn observer<O>(mut self, observer: O) -> Self
    where
        O: GuardObserver + 'static,
    {
        self.observer = Some(Arc::new(observer));
        self
    }

    pub fn allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = allowlist;
        self
    }

    #[must_use]
    pub fn build(self) -> GuardStack {
        GuardStack {
            inner: Arc::new(GuardStackInner {
                guards: self.guards,
                observer: self.observer,
                allowlist: self.allowlist,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::{Guard, GuardContext};
    use crate::SynError;
    use std::{net::SocketAddr, sync::{atomic::{AtomicUsize, Ordering}, Arc}};

    struct CountingGuard {
        reserves: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
        reject_on_reserve: bool,
    }

    impl Guard for CountingGuard {
        fn name(&self) -> &'static str { "counting" }
        fn on_reserve(&self, _ctx: &GuardContext) -> Result<(), SynError> {
            if self.reject_on_reserve {
                return Err(SynError::runtime("intentional reject"));
            }
            self.reserves.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn on_close(&self, _ctx: &GuardContext) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn ctx() -> GuardContext {
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        GuardContext::new(addr, None, false)
    }

    #[test]
    fn reserve_rollback_calls_on_close_for_accepted_guards() {
        let reserves = Arc::new(AtomicUsize::new(0));
        let closes = Arc::new(AtomicUsize::new(0));

        let first = CountingGuard {
            reserves: Arc::clone(&reserves),
            closes: Arc::clone(&closes),
            reject_on_reserve: false,
        };
        let second = CountingGuard {
            reserves: Arc::new(AtomicUsize::new(0)),
            closes: Arc::new(AtomicUsize::new(0)),
            reject_on_reserve: true,
        };

        let stack = GuardStack::builder().push(first).push(second).build();
        let result = stack.reserve(ctx());

        assert!(result.is_err(), "stack should reject");
        assert_eq!(reserves.load(Ordering::SeqCst), 1, "first guard reserved");
        assert_eq!(closes.load(Ordering::SeqCst), 1, "first guard must be closed on rollback");
    }

    #[test]
    fn allowlisted_ip_skips_all_guards() {
        let reserves = Arc::new(AtomicUsize::new(0));
        let closes = Arc::new(AtomicUsize::new(0));

        let guard = CountingGuard {
            reserves: Arc::clone(&reserves),
            closes: Arc::clone(&closes),
            reject_on_reserve: true,
        };

        let allowlist = Allowlist::new();
        allowlist.allow("127.0.0.1".parse().unwrap());

        let stack = GuardStack::builder().push(guard).allowlist(allowlist).build();
        let session = stack.reserve(ctx());

        assert!(session.is_ok(), "allowlisted IP must bypass guards");
        assert_eq!(reserves.load(Ordering::SeqCst), 0, "guard should not be called");

        drop(session);
        assert_eq!(closes.load(Ordering::SeqCst), 0, "guard on_close should not be called");
    }

    #[test]
    fn non_allowlisted_ip_still_checked() {
        let guard = CountingGuard {
            reserves: Arc::new(AtomicUsize::new(0)),
            closes: Arc::new(AtomicUsize::new(0)),
            reject_on_reserve: true,
        };

        let allowlist = Allowlist::new();
        allowlist.allow("10.0.0.1".parse().unwrap());

        let stack = GuardStack::builder().push(guard).allowlist(allowlist).build();
        let result = stack.reserve(ctx());

        assert!(result.is_err(), "non-allowlisted IP must still be checked");
    }

    #[test]
    fn allowlist_runtime_add_remove() {
        let allowlist = Allowlist::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(!allowlist.contains(&ip));
        allowlist.allow(ip);
        assert!(allowlist.contains(&ip));
        assert!(allowlist.remove(&ip));
        assert!(!allowlist.contains(&ip));
    }
}
