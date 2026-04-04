/// Ratchet header: DH public key (56 bytes) + prev_chain_len (u32) + msg_num (u32).
///
/// Wire format: dh_pub[56] || prev_chain_len[4 big-endian] || msg_num[4 big-endian]
/// Total: 64 bytes.

#[derive(Clone, Debug)]
pub struct RatchetHeader {
    pub dh_pub: [u8; 56],
    pub prev_chain_len: u32,
    pub msg_num: u32,
}

impl RatchetHeader {
    pub const SIZE: usize = 56 + 4 + 4; // 64 bytes

    pub fn new(dh_pub: [u8; 56], prev_chain_len: u32, msg_num: u32) -> Self {
        Self { dh_pub, prev_chain_len, msg_num }
    }

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..56].copy_from_slice(&self.dh_pub);
        buf[56..60].copy_from_slice(&self.prev_chain_len.to_be_bytes());
        buf[60..64].copy_from_slice(&self.msg_num.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, RatchetError> {
        if data.len() != Self::SIZE {
            return Err(RatchetError::InvalidHeader(
                format!("expected {} bytes, got {}", Self::SIZE, data.len()),
            ));
        }
        let mut dh_pub = [0u8; 56];
        dh_pub.copy_from_slice(&data[..56]);
        let prev_chain_len = u32::from_be_bytes([data[56], data[57], data[58], data[59]]);
        let msg_num = u32::from_be_bytes([data[60], data[61], data[62], data[63]]);
        Ok(Self { dh_pub, prev_chain_len, msg_num })
    }

    /// Extract DH public key from raw header bytes without full decode.
    pub fn peek_dh_pub(data: &[u8]) -> Option<&[u8]> {
        if data.len() >= 56 { Some(&data[..56]) } else { None }
    }
}

/// Errors from the double ratchet.
#[derive(Debug)]
pub enum RatchetError {
    /// Header decoding failed.
    InvalidHeader(String),
    /// AES-GCM decryption failed (wrong key, tampered, or replay).
    DecryptionFailed(String),
    /// Replay attack detected.
    ReplayDetected(String),
    /// Message number too old.
    MessageTooOld(String),
    /// Chain key is all zeros (KDF failure).
    ZeroChainKey,
    /// Max skip exceeded.
    MaxSkipExceeded(u32),
    /// Generic protocol error.
    Protocol(String),
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader(s) => write!(f, "invalid header: {s}"),
            Self::DecryptionFailed(s) => write!(f, "decryption failed: {s}"),
            Self::ReplayDetected(s) => write!(f, "replay detected: {s}"),
            Self::MessageTooOld(s) => write!(f, "message too old: {s}"),
            Self::ZeroChainKey => write!(f, "chain key is zero — KDF failure"),
            Self::MaxSkipExceeded(n) => write!(f, "max skip exceeded: {n}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
        }
    }
}

impl std::error::Error for RatchetError {}
