//! Ratchet header: DH public key (56) + prev_chain_len (u32) + msg_num (u32).
//!
//! Wire format: dh_pub[56] || prev_chain_len[4 BE] || msg_num[4 BE]  = 64 bytes.

use crate::error::SafeSlice;

#[derive(Clone, Debug)]
pub struct RatchetHeader {
    pub dh_pub: [u8; 56],
    pub prev_chain_len: u32,
    pub msg_num: u32,
}

impl RatchetHeader {
    pub const SIZE: usize = 56 + 4 + 4;

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
        let dh_slice = data.try_slice(0..56)
            .map_err(|_| RatchetError::InvalidHeader("truncated dh_pub".into()))?;
        dh_pub.copy_from_slice(dh_slice);

        let pcl_bytes: [u8; 4] = data.try_slice(56..60)
            .map_err(|_| RatchetError::InvalidHeader("truncated prev_chain_len".into()))?
            .try_into()
            .map_err(|_| RatchetError::InvalidHeader("internal: pcl slice".into()))?;
        let mn_bytes: [u8; 4] = data.try_slice(60..64)
            .map_err(|_| RatchetError::InvalidHeader("truncated msg_num".into()))?
            .try_into()
            .map_err(|_| RatchetError::InvalidHeader("internal: mn slice".into()))?;

        Ok(Self {
            dh_pub,
            prev_chain_len: u32::from_be_bytes(pcl_bytes),
            msg_num: u32::from_be_bytes(mn_bytes),
        })
    }

    pub fn peek_dh_pub(data: &[u8]) -> Option<&[u8]> {
        data.get(..56)
    }
}

#[cfg(feature = "test-only-kdf")]
#[pyo3::pyfunction]
#[pyo3(name = "encode_header")]
pub fn encode_header_py(
    dh_pub: &[u8],
    prev_chain_len: u32,
    msg_num: u32,
) -> pyo3::PyResult<Vec<u8>> {
    if dh_pub.len() != 56 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "dh_pub must be exactly 56 bytes",
        ));
    }
    let mut arr = [0u8; 56];
    arr.copy_from_slice(dh_pub);
    let h = RatchetHeader::new(arr, prev_chain_len, msg_num);
    Ok(h.encode().to_vec())
}

#[derive(Debug)]
pub enum RatchetError {
    InvalidHeader(String),
    DecryptionFailed(String),
    ReplayDetected(String),
    MessageTooOld(String),
    ZeroChainKey,
    MaxSkipExceeded(u32),
    Protocol(String),
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader(s)    => write!(f, "invalid header: {s}"),
            Self::DecryptionFailed(s) => write!(f, "decryption failed: {s}"),
            Self::ReplayDetected(s)   => write!(f, "replay detected: {s}"),
            Self::MessageTooOld(s)    => write!(f, "message too old: {s}"),
            Self::ZeroChainKey        => write!(f, "chain key is zero — KDF failure"),
            Self::MaxSkipExceeded(n)  => write!(f, "max skip exceeded: {n}"),
            Self::Protocol(s)         => write!(f, "protocol error: {s}"),
        }
    }
}

impl std::error::Error for RatchetError {}
