//! Length-prefixed frame IO over any [`Read`]/[`Write`]. A frame is a `u32`
//! big-endian byte length followed by that many bytes of JSON-encoded
//! [`crate::wire::Message`]. The declared length is bounded **before** any
//! allocation, so a hostile peer cannot name a huge buffer.

use std::io::{Read, Write};

use crate::wire::{Message, MAX_FRAME_BYTES};

/// Why a frame could not be read or written.
#[derive(Debug)]
pub enum CodecError {
    /// Underlying IO failure (includes a clean EOF mid-frame).
    Io(std::io::Error),
    /// The declared length exceeds [`MAX_FRAME_BYTES`]. The connection is not
    /// trusted to name a smaller buffer afterward, so the caller closes it.
    FrameTooLarge { declared: usize, max: usize },
    /// The frame bytes were not a valid [`Message`].
    Decode(serde_json::Error),
    /// The message serialized to more than [`MAX_FRAME_BYTES`] — a local bug or
    /// an oversized batch; refused rather than written truncated.
    EncodeTooLarge { size: usize, max: usize },
    /// The message could not be serialized.
    Encode(serde_json::Error),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Io(e) => write!(f, "io: {e}"),
            CodecError::FrameTooLarge { declared, max } => {
                write!(f, "frame declares {declared} bytes, cap is {max}")
            }
            CodecError::Decode(e) => write!(f, "decode: {e}"),
            CodecError::EncodeTooLarge { size, max } => {
                write!(f, "encoded message is {size} bytes, cap is {max}")
            }
            CodecError::Encode(e) => write!(f, "encode: {e}"),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<std::io::Error> for CodecError {
    fn from(e: std::io::Error) -> Self {
        CodecError::Io(e)
    }
}

/// Write one message as a length-prefixed JSON frame and flush it.
pub fn write_frame<W: Write>(w: &mut W, msg: &Message) -> Result<(), CodecError> {
    let body = serde_json::to_vec(msg).map_err(CodecError::Encode)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(CodecError::EncodeTooLarge {
            size: body.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    // `len` fits in u32 because it is <= MAX_FRAME_BYTES (4 MiB).
    let len = (body.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one length-prefixed JSON frame. Bounds the declared length before
/// allocating.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Message, CodecError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let declared = u32::from_be_bytes(len_buf) as usize;
    if declared > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge {
            declared,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut body = vec![0u8; declared];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(CodecError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Challenge, PROTOCOL_VERSION};

    #[test]
    fn roundtrip_through_a_byte_buffer() {
        let msg = Message::Challenge(Challenge {
            protocol_version: PROTOCOL_VERSION,
            nonce: [42u8; 32],
        });
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let got = read_frame(&mut cursor).unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn an_oversized_declared_length_is_refused_before_allocation() {
        // A 4-byte prefix declaring u32::MAX, and no body: must fail on the
        // bound, not attempt a 4 GiB allocation or block reading a body.
        let bytes = u32::MAX.to_be_bytes();
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        match read_frame(&mut cursor) {
            Err(CodecError::FrameTooLarge { declared, max }) => {
                assert_eq!(declared, u32::MAX as usize);
                assert_eq!(max, MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_frame_is_an_io_error_not_a_hang() {
        // Declares 10 bytes, provides 3. read_exact returns UnexpectedEof.
        let mut bytes = 10u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"abc");
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(matches!(read_frame(&mut cursor), Err(CodecError::Io(_))));
    }
}
