//! Fake delivery service: sees ciphertext, channel and membership events, as
//! the design table says. Replaced by the delivery service over MLS (W1 chat).

use std::collections::HashMap;

use crate::ports::{Delivery, Refusal, TapeRef};

/// What the delivery service holds per channel.
#[derive(Clone, Debug, Default)]
pub struct ChannelQueue {
    /// Ciphertexts in order.
    pub messages: Vec<String>,
    /// Membership events in order (visible by design).
    pub events: Vec<String>,
}

/// The fake delivery service.
pub struct FakeDelivery {
    tape: TapeRef,
    /// Queues per channel.
    pub channels: HashMap<String, ChannelQueue>,
}

impl FakeDelivery {
    /// New.
    pub fn new(tape: TapeRef) -> Self {
        Self {
            tape,
            channels: HashMap::new(),
        }
    }
}

impl Delivery for FakeDelivery {
    fn send(&mut self, channel: &str, ciphertext: &str) -> Result<(), Refusal> {
        self.tape
            .borrow_mut()
            .see("delivery", "send", &(channel, ciphertext));
        if !ciphertext.starts_with("ct_") {
            return Err(Refusal("delivery only carries ciphertext".into()));
        }
        self.channels
            .entry(channel.to_string())
            .or_default()
            .messages
            .push(ciphertext.to_string());
        Ok(())
    }

    fn membership(&mut self, channel: &str, event: &str) -> Result<(), Refusal> {
        self.tape
            .borrow_mut()
            .see("delivery", "membership", &(channel, event));
        self.channels
            .entry(channel.to_string())
            .or_default()
            .events
            .push(event.to_string());
        Ok(())
    }
}
