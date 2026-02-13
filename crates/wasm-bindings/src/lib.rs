use wasm_bindgen::prelude::*;

// === Standalone crypto functions ===

#[wasm_bindgen(js_name = "blake3Hash")]
pub fn js_blake3_hash(data: &[u8]) -> Vec<u8> {
    crypto_primitives::blake3_hash(data).to_vec()
}

#[wasm_bindgen(js_name = "blake3HashHex")]
pub fn js_blake3_hash_hex(data: &[u8]) -> String {
    crypto_primitives::blake3_hash_hex(data)
}

#[wasm_bindgen(js_name = "blake3DeriveKey")]
pub fn js_blake3_derive_key(context: &str, ikm: &[u8]) -> Vec<u8> {
    crypto_primitives::blake3_derive_key(context, ikm).to_vec()
}

#[wasm_bindgen(js_name = "blake3KeyedHash")]
pub fn js_blake3_keyed_hash(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be exactly 32 bytes"));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);
    Ok(crypto_primitives::blake3_keyed_hash(&key_arr, data).to_vec())
}

#[wasm_bindgen(js_name = "randomBytes")]
pub fn js_random_bytes(len: usize) -> Result<Vec<u8>, JsError> {
    crypto_primitives::random_bytes(len)
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = "randomHex")]
pub fn js_random_hex(byte_len: usize) -> Result<String, JsError> {
    crypto_primitives::random_hex(byte_len)
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = "generateSessionId")]
pub fn js_generate_session_id() -> Result<Vec<u8>, JsError> {
    crypto_primitives::generate_session_id()
        .map(|id| id.to_vec())
        .map_err(|e| JsError::new(&e.to_string()))
}

// === Address utilities ===

#[wasm_bindgen(js_name = "classifyAddress")]
pub fn js_classify_address(addr: &str) -> String {
    format!("{:?}", address_utils::classify_address(addr))
}

#[wasm_bindgen(js_name = "supportsMemos")]
pub fn js_supports_memos(addr: &str) -> bool {
    address_utils::supports_memos(addr)
}

#[wasm_bindgen(js_name = "isShielded")]
pub fn js_is_shielded(addr: &str) -> bool {
    address_utils::is_shielded(addr)
}

#[wasm_bindgen(js_name = "validateAddress")]
pub fn js_validate_address(addr: &str) -> bool {
    address_utils::validate_address(addr)
}

#[wasm_bindgen(js_name = "agentIdFromPubkey")]
pub fn js_agent_id_from_pubkey(pubkey: &[u8]) -> Result<String, JsError> {
    if pubkey.len() != 32 {
        return Err(JsError::new("pubkey must be exactly 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(pubkey);
    Ok(address_utils::agent_id_from_pubkey(&arr))
}

// === AgentKeyPair wrapper ===

#[wasm_bindgen]
pub struct WasmAgentKeyPair {
    inner: crypto_primitives::AgentKeyPair,
}

impl Default for WasmAgentKeyPair {
    fn default() -> Self {
        Self {
            inner: crypto_primitives::AgentKeyPair::generate(),
        }
    }
}

#[wasm_bindgen]
impl WasmAgentKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmAgentKeyPair {
        Self::default()
    }

    #[wasm_bindgen(js_name = "publicKeyBytes")]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }

    #[wasm_bindgen(js_name = "diffieHellman")]
    pub fn diffie_hellman(&self, peer_public: &[u8]) -> Result<Vec<u8>, JsError> {
        if peer_public.len() != 32 {
            return Err(JsError::new("peer public key must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(peer_public);
        Ok(self.inner.diffie_hellman(&arr).to_vec())
    }
}

#[wasm_bindgen]
pub struct WasmRatchetState {
    inner: crypto_primitives::RatchetState,
}

#[wasm_bindgen]
impl WasmRatchetState {
    #[wasm_bindgen(constructor)]
    pub fn new(root_key: &[u8]) -> Result<WasmRatchetState, JsError> {
        if root_key.len() != 32 {
            return Err(JsError::new("root_key must be 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(root_key);
        Ok(WasmRatchetState {
            inner: crypto_primitives::RatchetState::new(key),
        })
    }

    #[wasm_bindgen(js_name = ratchetForward)]
    pub fn ratchet_forward(&mut self) -> Result<JsValue, JsError> {
        let (key, index) = self.inner.ratchet_forward();
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &"messageKey".into(),
            &hex::encode(key).into(),
        )
        .map_err(jsval_err)?;
        js_sys::Reflect::set(
            &obj,
            &"messageIndex".into(),
            &JsValue::from_f64(index as f64),
        )
        .map_err(jsval_err)?;
        Ok(obj.into())
    }

    #[wasm_bindgen(js_name = getMessageKey)]
    pub fn get_message_key(&mut self, index: u64) -> Result<String, JsError> {
        let key = self
            .inner
            .get_message_key(index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(hex::encode(key))
    }
}

#[wasm_bindgen]
pub struct WasmRotatingKeyPair {
    inner: crypto_primitives::RotatingKeyPair,
}

#[wasm_bindgen]
impl WasmRotatingKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(created_at: u64) -> Result<WasmRotatingKeyPair, JsError> {
        let inner = crypto_primitives::RotatingKeyPair::new(created_at)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(WasmRotatingKeyPair { inner })
    }

    pub fn rotate(&mut self, now: u64) -> Result<(), JsError> {
        self.inner
            .rotate(now)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = currentPublicKey)]
    pub fn current_public_key(&self) -> String {
        hex::encode(self.inner.current_public_key())
    }

    pub fn generation(&self) -> u32 {
        self.inner.generation()
    }

    #[wasm_bindgen(js_name = shouldRotate)]
    pub fn should_rotate(&self, max_age_secs: u64, max_messages: u32, _now: u64) -> bool {
        self.inner.should_rotate(max_age_secs, max_messages)
    }
}

#[wasm_bindgen(js_name = deriveAgentFromSeed)]
pub fn derive_agent_from_seed(
    seed: &[u8],
    agent_index: u32,
) -> Result<WasmAgentKeyPair, JsError> {
    if seed.len() != 32 {
        return Err(JsError::new("seed must be 32 bytes"));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(seed);
    let keypair =
        crypto_primitives::AgentKeyDerivation::from_seed(&seed_arr, agent_index)
            .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(WasmAgentKeyPair { inner: keypair })
}

#[wasm_bindgen(js_name = agentIdFromSeed)]
pub fn agent_id_from_seed(seed: &[u8], agent_index: u32) -> Result<String, JsError> {
    if seed.len() != 32 {
        return Err(JsError::new("seed must be 32 bytes"));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(seed);
    let id = crypto_primitives::AgentKeyDerivation::agent_id_from_seed(&seed_arr, agent_index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex::encode(id))
}

// === AgentCipher wrapper ===

#[wasm_bindgen]
pub struct WasmAgentCipher {
    inner: crypto_primitives::AgentCipher,
}

#[wasm_bindgen]
impl WasmAgentCipher {
    #[wasm_bindgen(constructor)]
    pub fn new(shared_secret: &[u8]) -> Result<WasmAgentCipher, JsError> {
        if shared_secret.len() != 32 {
            return Err(JsError::new("shared secret must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(shared_secret);
        Ok(WasmAgentCipher {
            inner: crypto_primitives::AgentCipher::new(&arr),
        })
    }

    #[wasm_bindgen(js_name = "fromKey")]
    pub fn from_key(key: &[u8]) -> Result<WasmAgentCipher, JsError> {
        if key.len() != 32 {
            return Err(JsError::new("key must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        Ok(WasmAgentCipher {
            inner: crypto_primitives::AgentCipher::from_key(arr),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .encrypt(plaintext)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .decrypt(data)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = "encryptHex")]
    pub fn encrypt_hex(&self, plaintext: &[u8]) -> Result<String, JsError> {
        self.inner
            .encrypt_hex(plaintext)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = "decryptHex")]
    pub fn decrypt_hex(&self, hex_str: &str) -> Result<Vec<u8>, JsError> {
        self.inner
            .decrypt_hex(hex_str)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

// === Memo encoding/decoding ===

#[wasm_bindgen(js_name = "encodeMemos")]
pub fn js_encode_memos(
    data: &[u8],
    msg_type: u8,
    session_id: &[u8],
) -> Result<Vec<u8>, JsError> {
    let mt = memo_codec::MessageType::try_from(msg_type)
        .map_err(|_| JsError::new(&format!("invalid message type: 0x{:02X}", msg_type)))?;
    let sid = to_session_id(session_id)?;
    let memos = memo_codec::chunk_message(data, mt, &sid)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(flatten_memos(&memos))
}

#[wasm_bindgen(js_name = "decodeMemos")]
pub fn js_decode_memos(flat_memos: &[u8]) -> Result<JsValue, JsError> {
    let memos = unflatten_memos(flat_memos)?;
    let msg = memo_codec::decode_chunked_message(&memos)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"sessionId".into(), &hex::encode(msg.session_id).into())
        .map_err(jsval_err)?;
    js_sys::Reflect::set(&obj, &"msgType".into(), &(msg.msg_type as u8).into())
        .map_err(jsval_err)?;
    js_sys::Reflect::set(
        &obj,
        &"data".into(),
        &js_sys::Uint8Array::from(msg.data.as_slice()).into(),
    )
    .map_err(jsval_err)?;
    js_sys::Reflect::set(
        &obj,
        &"contentHash".into(),
        &hex::encode(msg.content_hash).into(),
    )
    .map_err(jsval_err)?;
    Ok(obj.into())
}

// === Handshake ===

#[wasm_bindgen(js_name = "createHandshake")]
pub fn js_create_handshake(
    keypair: &WasmAgentKeyPair,
    capabilities: JsValue,
) -> Result<JsValue, JsError> {
    let caps: Vec<String> = serde_wasm_bindgen::from_value(capabilities)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let cap_refs: Vec<&str> = caps.iter().map(|s| s.as_str()).collect();
    let handshake = agent_protocol::create_handshake(&keypair.inner, &cap_refs);
    serde_wasm_bindgen::to_value(&handshake).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = "encodeHandshake")]
pub fn js_encode_handshake(
    handshake_json: JsValue,
    session_id: &[u8],
) -> Result<Vec<u8>, JsError> {
    let handshake: agent_protocol::AgentHandshake =
        serde_wasm_bindgen::from_value(handshake_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let sid = to_session_id(session_id)?;
    let memos = agent_protocol::encode_handshake(&handshake, &sid)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(flatten_memos(&memos))
}

#[wasm_bindgen(js_name = "decodeHandshake")]
pub fn js_decode_handshake(flat_memos: &[u8]) -> Result<JsValue, JsError> {
    let memos = unflatten_memos(flat_memos)?;
    let handshake =
        agent_protocol::decode_handshake(&memos).map_err(|e| JsError::new(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&handshake).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = "completeHandshake")]
pub fn js_complete_handshake(
    keypair: &WasmAgentKeyPair,
    handshake_json: JsValue,
) -> Result<Vec<u8>, JsError> {
    let handshake: agent_protocol::AgentHandshake =
        serde_wasm_bindgen::from_value(handshake_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let secret = agent_protocol::complete_handshake(&keypair.inner, &handshake)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(secret.to_vec())
}

// === Task/Bounty ===

#[wasm_bindgen(js_name = "encodeTaskAssignment")]
pub fn js_encode_task_assignment(
    task_json: JsValue,
    session_id: &[u8],
) -> Result<Vec<u8>, JsError> {
    let task: agent_protocol::TaskAssignment = serde_wasm_bindgen::from_value(task_json)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sid = to_session_id(session_id)?;
    let memos = agent_protocol::encode_task_assignment(&task, &sid)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(flatten_memos(&memos))
}

#[wasm_bindgen(js_name = "encodeTaskProof")]
pub fn js_encode_task_proof(
    proof_json: JsValue,
    session_id: &[u8],
) -> Result<Vec<u8>, JsError> {
    let proof: agent_protocol::TaskProof = serde_wasm_bindgen::from_value(proof_json)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sid = to_session_id(session_id)?;
    let memos = agent_protocol::encode_task_proof(&proof, &sid)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(flatten_memos(&memos))
}

#[wasm_bindgen(js_name = "encodePaymentConfirmation")]
pub fn js_encode_payment_confirmation(
    payment_json: JsValue,
    session_id: &[u8],
) -> Result<Vec<u8>, JsError> {
    let payment: agent_protocol::PaymentConfirmation =
        serde_wasm_bindgen::from_value(payment_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let sid = to_session_id(session_id)?;
    let memos = agent_protocol::encode_payment_confirmation(&payment, &sid)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(flatten_memos(&memos))
}

#[wasm_bindgen(js_name = "decodeTaskMessage")]
pub fn js_decode_task_message(flat_memos: &[u8]) -> Result<JsValue, JsError> {
    let memos = unflatten_memos(flat_memos)?;
    let task_msg =
        agent_protocol::decode_task_message(&memos).map_err(|e| JsError::new(&e.to_string()))?;

    let obj = js_sys::Object::new();
    match task_msg {
        agent_protocol::TaskMessage::Assignment(t) => {
            js_sys::Reflect::set(&obj, &"type".into(), &"assignment".into())
                .map_err(jsval_err)?;
            let data =
                serde_wasm_bindgen::to_value(&t).map_err(|e| JsError::new(&e.to_string()))?;
            js_sys::Reflect::set(&obj, &"data".into(), &data).map_err(jsval_err)?;
        }
        agent_protocol::TaskMessage::Proof(p) => {
            js_sys::Reflect::set(&obj, &"type".into(), &"proof".into())
                .map_err(jsval_err)?;
            let data =
                serde_wasm_bindgen::to_value(&p).map_err(|e| JsError::new(&e.to_string()))?;
            js_sys::Reflect::set(&obj, &"data".into(), &data).map_err(jsval_err)?;
        }
        agent_protocol::TaskMessage::Payment(p) => {
            js_sys::Reflect::set(&obj, &"type".into(), &"payment".into())
                .map_err(jsval_err)?;
            let data =
                serde_wasm_bindgen::to_value(&p).map_err(|e| JsError::new(&e.to_string()))?;
            js_sys::Reflect::set(&obj, &"data".into(), &data).map_err(jsval_err)?;
        }
    }
    Ok(obj.into())
}

#[wasm_bindgen(js_name = "createTaskProof")]
pub fn js_create_task_proof(
    task_id: &str,
    action: &str,
    proof_data: &[u8],
    timestamp: f64,
) -> Result<JsValue, JsError> {
    let proof =
        agent_protocol::create_task_proof(task_id, action, proof_data, timestamp as u64);
    serde_wasm_bindgen::to_value(&proof).map_err(|e| JsError::new(&e.to_string()))
}

// === Version ===

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// === Helpers (not exported) ===

/// Convert a JsValue error (from js_sys::Reflect) into a JsError.
fn jsval_err(val: JsValue) -> JsError {
    JsError::new(&format!("{:?}", val))
}

fn to_session_id(bytes: &[u8]) -> Result<[u8; 16], JsError> {
    if bytes.len() != 16 {
        return Err(JsError::new("session_id must be 16 bytes"));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

fn flatten_memos(memos: &[[u8; 512]]) -> Vec<u8> {
    let mut result = Vec::with_capacity(memos.len() * 512);
    for memo in memos {
        result.extend_from_slice(memo);
    }
    result
}

fn unflatten_memos(flat: &[u8]) -> Result<Vec<[u8; 512]>, JsError> {
    if !flat.len().is_multiple_of(512) || flat.is_empty() {
        return Err(JsError::new(
            "memos must be a non-empty multiple of 512 bytes",
        ));
    }
    let count = flat.len() / 512;
    let mut memos = Vec::with_capacity(count);
    for i in 0..count {
        let mut memo = [0u8; 512];
        memo.copy_from_slice(&flat[i * 512..(i + 1) * 512]);
        memos.push(memo);
    }
    Ok(memos)
}
