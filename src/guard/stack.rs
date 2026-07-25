use std::{sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Instant};

use crate::{guard::{Guard, GuardContext, GuardDecision, GuardEvent, GuardEventKind, GuardObserver}, SynError};

struct GuardStackInner {
    guards: Vec<Arc<dyn Guard>>,
    observer: Option<Arc<dyn GuardObserver>>,
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
            }),
        }
    }

    pub fn reserve(&self, context: GuardContext) -> Result<GuardSession, SynError> {
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
        })
    }
}

pub struct GuardSession {
    inner: Arc<GuardStackInner>,
    context: GuardContext,
    closed: AtomicBool,
    established: AtomicBool,
}

impl GuardSession {
    pub fn mark_established(&self) -> Result<(), SynError> {
        if self.established.swap(true, Ordering::SeqCst) {
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
        if self.closed.swap(true, Ordering::SeqCst) {
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

    #[must_use]
    pub fn build(self) -> GuardStack {
        GuardStack {
            inner: Arc::new(GuardStackInner {
                guards: self.guards,
                observer: self.observer,
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
}
