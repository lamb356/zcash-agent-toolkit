use std::collections::HashMap;

use crate::chunk::{decode_memo, encode_memo, MemoError, MemoHeader};
use crate::types::{MessageType, MEMO_SIZE, PAYLOAD_SIZE, PROTOCOL_VERSION};
#[cfg(test)]
use crate::types::HEADER_SIZE;

/// A fully reassembled multi-chunk message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledMessage {
    /// Session identifier from the memo headers.
    pub session_id: [u8; 16],
    /// Message type.
    pub msg_type: MessageType,
    /// The reassembled payload bytes.
    pub data: Vec<u8>,
    /// BLAKE3 hash that was declared in the headers.
    pub content_hash: [u8; 32],
}

/// Split `data` into a sequence of 512-byte memos.
///
/// Computes a BLAKE3 hash over the full original `data`, then produces one memo per
/// `PAYLOAD_SIZE`-byte chunk. Each chunk records its exact payload length in the header.
///
/// Returns an error if the message is too large (would require more than u16::MAX chunks).
pub fn chunk_message(
    data: &[u8],
    msg_type: MessageType,
    session_id: &[u8; 16],
) -> Result<Vec<[u8; MEMO_SIZE]>, MemoError> {
    let content_hash: [u8; 32] = *blake3::hash(data).as_bytes();

    let chunks: Vec<&[u8]> = if data.is_empty() {
        // Even an empty message produces one chunk.
        vec![&[]]
    } else {
        data.chunks(PAYLOAD_SIZE).collect()
    };

    if chunks.len() > u16::MAX as usize {
        return Err(MemoError::MessageTooLarge {
            max_bytes: u16::MAX as usize * PAYLOAD_SIZE,
            actual_bytes: data.len(),
        });
    }

    let total_chunks = chunks.len() as u16;

    let memos = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let header = MemoHeader {
                version: PROTOCOL_VERSION,
                msg_type,
                session_id: *session_id,
                chunk_index: i as u16,
                total_chunks,
                content_hash,
                payload_length: chunk.len() as u16,
            };
            encode_memo(&header, chunk).expect("chunk size <= PAYLOAD_SIZE by construction")
        })
        .collect();

    Ok(memos)
}

/// Convenience function: decode a complete set of memos into a single message.
///
/// All memos must belong to the same session. The content hash is verified
/// against the reassembled data.
pub fn decode_chunked_message(memos: &[[u8; MEMO_SIZE]]) -> Result<ReassembledMessage, MemoError> {
    if memos.is_empty() {
        return Err(MemoError::MissingChunks {
            expected: 1,
            received: 0,
        });
    }

    // Decode all headers and payloads.
    let decoded: Vec<(MemoHeader, Vec<u8>)> = memos
        .iter()
        .map(decode_memo)
        .collect::<Result<Vec<_>, _>>()?;

    let first = &decoded[0].0;
    let session_id = first.session_id;
    let msg_type = first.msg_type;
    let content_hash = first.content_hash;
    let total_chunks = first.total_chunks;

    // Validate all headers are consistent.
    let mut seen_indices = std::collections::HashSet::new();
    for (hdr, _) in &decoded {
        if hdr.session_id != session_id {
            return Err(MemoError::SessionIdMismatch);
        }
        if hdr.msg_type != msg_type || hdr.content_hash != content_hash || hdr.total_chunks != total_chunks {
            return Err(MemoError::InconsistentChunks);
        }
        if hdr.chunk_index >= total_chunks {
            return Err(MemoError::InvalidChunkIndex {
                index: hdr.chunk_index,
                total: total_chunks,
            });
        }
        if !seen_indices.insert(hdr.chunk_index) {
            return Err(MemoError::DuplicateChunkIndex(hdr.chunk_index));
        }
    }

    if decoded.len() != total_chunks as usize {
        return Err(MemoError::MissingChunks {
            expected: total_chunks,
            received: decoded.len() as u16,
        });
    }

    // Sort by chunk_index and reassemble using exact payload_length from each chunk.
    let mut sorted = decoded;
    sorted.sort_by_key(|(hdr, _)| hdr.chunk_index);

    let mut data = Vec::new();
    for (_hdr, payload) in &sorted {
        data.extend_from_slice(payload);
    }

    // Verify BLAKE3 hash.
    let computed: [u8; 32] = *blake3::hash(&data).as_bytes();
    if computed != content_hash {
        return Err(MemoError::ContentHashMismatch);
    }

    Ok(ReassembledMessage {
        session_id,
        msg_type,
        data,
        content_hash,
    })
}

/// Incremental reassembly buffer for receiving chunks out of order.
///
/// Chunks are keyed by `(session_id, chunk_index)`. When all chunks for a
/// session have been received the message is reassembled and returned.
///
/// Enforces a maximum number of concurrent sessions to prevent memory exhaustion.
#[derive(Debug)]
pub struct ReassemblyBuffer {
    /// Map from session_id to a map from chunk_index to (header, payload).
    sessions: HashMap<[u8; 16], HashMap<u16, (MemoHeader, Vec<u8>)>>,
    /// Maximum number of concurrent sessions.
    max_sessions: usize,
    /// Track creation order for eviction (session_id, insertion order).
    insertion_order: Vec<[u8; 16]>,
}

impl Default for ReassemblyBuffer {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions: 256,
            insertion_order: Vec::new(),
        }
    }
}

impl ReassemblyBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a buffer with a custom maximum session limit.
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
            insertion_order: Vec::new(),
        }
    }

    /// Add a single 512-byte memo chunk.
    ///
    /// Returns `Ok(Some(msg))` when the last missing chunk for a session
    /// arrives and the message is successfully reassembled (with hash
    /// verification). Returns `Ok(None)` if more chunks are still needed.
    pub fn add_chunk(
        &mut self,
        memo: &[u8; MEMO_SIZE],
    ) -> Result<Option<ReassembledMessage>, MemoError> {
        let (header, payload) = decode_memo(memo)?;

        let session_id = header.session_id;
        let total_chunks = header.total_chunks;
        let chunk_index = header.chunk_index;

        if chunk_index >= total_chunks {
            return Err(MemoError::InvalidChunkIndex {
                index: chunk_index,
                total: total_chunks,
            });
        }

        let is_new_session = !self.sessions.contains_key(&session_id);
        if is_new_session && self.sessions.len() >= self.max_sessions {
            // Evict the oldest session.
            if let Some(oldest) = self.insertion_order.first().copied() {
                self.sessions.remove(&oldest);
                self.insertion_order.remove(0);
            }
        }

        let session = self.sessions.entry(session_id).or_default();
        if session.contains_key(&chunk_index) {
            return Err(MemoError::DuplicateChunkIndex(chunk_index));
        }
        session.insert(chunk_index, (header, payload));
        if is_new_session {
            self.insertion_order.push(session_id);
        }

        if session.len() == total_chunks as usize {
            // All chunks received -- take ownership and reassemble.
            let chunks = self.sessions.remove(&session_id).unwrap();
            self.insertion_order.retain(|id| *id != session_id);
            let msg_type = chunks.values().next().unwrap().0.msg_type;
            let content_hash = chunks.values().next().unwrap().0.content_hash;

            let mut sorted: Vec<(u16, Vec<u8>)> = chunks
                .into_iter()
                .map(|(idx, (_hdr, payload))| (idx, payload))
                .collect();
            sorted.sort_by_key(|(idx, _)| *idx);

            let mut data = Vec::new();
            for (_, payload) in &sorted {
                data.extend_from_slice(payload);
            }

            // Verify hash.
            let computed: [u8; 32] = *blake3::hash(&data).as_bytes();
            if computed != content_hash {
                return Err(MemoError::ContentHashMismatch);
            }

            Ok(Some(ReassembledMessage {
                session_id,
                msg_type,
                data,
                content_hash,
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_id() -> [u8; 16] {
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
    }

    #[test]
    fn single_chunk_for_small_data() {
        let data = b"hello world";
        let memos = chunk_message(data, MessageType::Text, &test_session_id()).unwrap();
        assert_eq!(memos.len(), 1);
    }

    #[test]
    fn two_chunks_for_453_bytes() {
        let data = vec![0x42u8; 453];
        let memos = chunk_message(&data, MessageType::Text, &test_session_id()).unwrap();
        assert_eq!(memos.len(), 2);
    }

    #[test]
    fn correct_chunk_count_for_1000_bytes() {
        let data = vec![0x42u8; 1000];
        let memos = chunk_message(&data, MessageType::Text, &test_session_id()).unwrap();
        // ceil(1000 / 452) = 3
        assert_eq!(memos.len(), 3);
    }

    #[test]
    fn roundtrip_5kb() {
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let sid = test_session_id();
        let memos = chunk_message(&data, MessageType::Text, &sid).unwrap();
        let msg = decode_chunked_message(&memos).expect("decode");
        assert_eq!(msg.data, data);
        assert_eq!(msg.session_id, sid);
        assert_eq!(msg.msg_type, MessageType::Text);
    }

    #[test]
    fn roundtrip_10kb() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let sid = test_session_id();
        let memos = chunk_message(&data, MessageType::Command, &sid).unwrap();
        let msg = decode_chunked_message(&memos).expect("decode");
        assert_eq!(msg.data, data);
    }

    #[test]
    fn tampered_payload_fails_hash_check() {
        let data = b"important message content that should be verified";
        let sid = test_session_id();
        let mut memos = chunk_message(data, MessageType::Text, &sid).unwrap();

        // Tamper with a byte inside the actual payload region (after the 60-byte header).
        memos[0][HEADER_SIZE] ^= 0xFF;

        let err = decode_chunked_message(&memos).unwrap_err();
        assert_eq!(err, MemoError::ContentHashMismatch);
    }

    #[test]
    fn session_id_mismatch_fails() {
        let data = vec![0xAA; 500]; // produces 2 chunks
        let sid1 = [0x01; 16];
        let sid2 = [0x02; 16];

        let memos1 = chunk_message(&data, MessageType::Text, &sid1).unwrap();
        let memos2 = chunk_message(&data, MessageType::Text, &sid2).unwrap();

        // Mix chunk 0 from session 1 with chunk 1 from session 2.
        let mixed = vec![memos1[0], memos2[1]];
        let err = decode_chunked_message(&mixed).unwrap_err();
        assert_eq!(err, MemoError::SessionIdMismatch);
    }

    #[test]
    fn reassembly_buffer_returns_none_until_complete() {
        let data = vec![0x42u8; 1000]; // 3 chunks
        let sid = test_session_id();
        let memos = chunk_message(&data, MessageType::Text, &sid).unwrap();
        assert_eq!(memos.len(), 3);

        let mut buf = ReassemblyBuffer::new();

        let r1 = buf.add_chunk(&memos[0]).expect("add chunk 0");
        assert!(r1.is_none());

        let r2 = buf.add_chunk(&memos[1]).expect("add chunk 1");
        assert!(r2.is_none());

        let r3 = buf.add_chunk(&memos[2]).expect("add chunk 2");
        assert!(r3.is_some());

        let msg = r3.unwrap();
        assert_eq!(msg.data, data);
        assert_eq!(msg.session_id, sid);
    }

    #[test]
    fn reassembly_buffer_out_of_order() {
        let data = vec![0x42u8; 1000]; // 3 chunks
        let sid = test_session_id();
        let memos = chunk_message(&data, MessageType::Text, &sid).unwrap();

        let mut buf = ReassemblyBuffer::new();

        // Feed in reverse order.
        assert!(buf.add_chunk(&memos[2]).expect("add").is_none());
        assert!(buf.add_chunk(&memos[0]).expect("add").is_none());
        let result = buf.add_chunk(&memos[1]).expect("add");
        assert!(result.is_some());

        let msg = result.unwrap();
        assert_eq!(msg.data, data);
    }

    #[test]
    fn unicode_text_roundtrip() {
        let text = "Hello, world! Bonjour le monde! \u{1F600} \u{4e16}\u{754c}\u{4f60}\u{597d}";
        let data = text.as_bytes();
        let sid = test_session_id();
        let memos = chunk_message(data, MessageType::Text, &sid).unwrap();
        let msg = decode_chunked_message(&memos).expect("decode");
        let recovered = std::str::from_utf8(&msg.data).expect("valid utf-8");
        assert_eq!(recovered, text);
    }

    #[test]
    fn json_roundtrip() {
        let value = serde_json::json!({
            "action": "transfer",
            "amount": 1.5,
            "to": "zs1abc...",
            "nested": { "flag": true, "items": [1, 2, 3] }
        });
        let data = serde_json::to_vec(&value).expect("serialize");
        let sid = test_session_id();
        let memos = chunk_message(&data, MessageType::Command, &sid).unwrap();
        let msg = decode_chunked_message(&memos).expect("decode");
        let recovered: serde_json::Value = serde_json::from_slice(&msg.data).expect("deserialize");
        assert_eq!(recovered, value);
    }

    #[test]
    fn empty_memos_returns_error() {
        let empty: &[[u8; MEMO_SIZE]] = &[];
        let err = decode_chunked_message(empty).unwrap_err();
        assert!(matches!(err, MemoError::MissingChunks { .. }));
    }

    #[test]
    fn empty_data_produces_one_chunk() {
        let data = b"";
        let sid = test_session_id();
        let memos = chunk_message(data, MessageType::Ack, &sid).unwrap();
        assert_eq!(memos.len(), 1);

        let msg = decode_chunked_message(&memos).expect("decode");
        assert!(msg.data.is_empty());
    }
}
