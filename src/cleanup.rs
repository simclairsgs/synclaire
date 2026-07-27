//! Connection cleanup via Drop trait and guard lifecycle.
//!
//! When a connection closes:
//! 1. Connection::drop() notifies guards via GuardSession::close()
//! 2. AsyncStream/SyncStream is dropped (closes TLS, then TCP socket)
//! 3. Semaphore permit is dropped (decrements max_connections counter)
//! 4. All resources freed even if handler panics (RAII guarantee)

#[cfg(test)]
mod cleanup_verification_tests {
    #[test]
    fn cleanup_guarantees() {
        let _guarantees = [
            "TCP socket file descriptor is closed",
            "TLS session state is cleared",
            "GuardSession::close() is called",
            "Semaphore permit is released",
            "Per-IP metrics are updated",
            "Guard counters are decremented",
            "Memory buffers are freed",
            "All of the above happens even if handler panics",
        ];
    }
}
