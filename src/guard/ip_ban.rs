use std::{collections::HashSet, net::IpAddr};

use parking_lot::Mutex;

use crate::{guard::{Guard, GuardContext}, SynError};

#[derive(Clone, Debug, Default)]
pub struct IpBanConfig {}

pub struct IpBan {
    banned: Mutex<HashSet<IpAddr>>,
}

impl IpBan {
    pub fn new(_config: IpBanConfig) -> Self {
        Self {
            banned: Mutex::new(HashSet::new()),
        }
    }

    pub fn ban(&self, ip: IpAddr) {
        self.banned.lock().insert(ip);
    }

    pub fn unban(&self, ip: &IpAddr) {
        self.banned.lock().remove(ip);
    }

    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        self.banned.lock().contains(ip)
    }

}

impl Guard for IpBan {
    fn name(&self) -> &'static str {
        "ip_ban"
    }

    fn on_reserve(&self, context: &GuardContext) -> Result<(), SynError> {
        if self.is_banned(&context.peer_ip) {
            return Err(SynError::BannedIp(context.peer_ip.to_string()));
        }

        Ok(())
    }
}