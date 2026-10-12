//! Ruby bindings for vodozemac (Matrix Olm/Megolm), via magnus.
//!
//! This is the Ruby analogue of matrix-nio/vodozemac-python (which uses PyO3).
//! It exposes vodozemac's Account / Session (Olm), GroupSession /
//! InboundGroupSession (Megolm), Sas, the ed25519 and curve25519 key types and
//! PkEncryption / PkDecryption, under the `Vodozemac` module.
//!
//! The API is deliberately base64-string / integer centric rather than passing
//! wrapped key objects around: Matrix moves keys and ciphertext as base64
//! strings inside JSON, so a string API drops straight into the protocol layer
//! and keeps the magnus surface small. The key types are bound as classes too,
//! for the caller which wants to parse one before handing it on, but every
//! method takes and returns base64.
//!
//! # Provenance
//!
//! matrix-rust-sdk is the reference for how these primitives are driven, and it
//! is licensed Apache-2.0, as this project is. Logic may therefore be ported
//! from it directly: section 4(b) of the licence asks that a derived file carry
//! a prominent notice of the change, so a method which follows its logic says
//! so where it appears, and the root NOTICE records the attribution.
//!
//! Fractal is worth reading for how a client sequences these calls, but it is
//! GPL-3.0-or-later. Nothing may be copied from it into this file.
//!
//!   - <https://github.com/matrix-org/matrix-rust-sdk> (Apache-2.0)
//!   - <https://github.com/matrix-org/vodozemac> (Apache-2.0)
//!   - <https://gitlab.gnome.org/World/fractal> (GPL-3.0-or-later; read only)

use std::cell::RefCell;
use std::collections::HashMap;

use magnus::{function, method, prelude::*, Error, Ruby};

use vodozemac_core::{
    base64_decode, base64_encode, Curve25519PublicKey as Curve25519Public,
    Curve25519SecretKey as Curve25519Secret, Ed25519Keypair as Ed25519Pair,
    Ed25519PublicKey as Ed25519Public, Ed25519SecretKey as Ed25519Secret,
    Ed25519Signature as Ed25519Sig,
};
use vodozemac_core::olm::{
    Account as OlmAccount, AccountPickle, OlmMessage, PreKeyMessage, Session as OlmSession,
    SessionConfig as OlmSessionConfig, SessionPickle,
};
use vodozemac_core::megolm::{
    ExportedSessionKey, GroupSession as MegolmGroupSession, GroupSessionPickle,
    InboundGroupSession as MegolmInbound, InboundGroupSessionPickle, MegolmMessage,
    SessionConfig as MegolmSessionConfig, SessionKey,
};
use vodozemac_core::pk_encryption::{
    Message as PkMessage, PkDecryption as PkDecrypt, PkEncryption as PkEncrypt,
};

// --- helpers ---------------------------------------------------------------

fn rt_err<E: std::fmt::Display>(e: E) -> Error {
    // Safe: every caller runs inside a Ruby method invocation (GVL held).
    let ruby = Ruby::get().expect("rt_err called outside the Ruby VM");
    Error::new(ruby.exception_runtime_error(), e.to_string())
}

fn key32(label: &str, bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| rt_err(format!("{label} must be 32 bytes, got {}", bytes.len())))
}

/// Decode a base64 string into the 32 bytes a raw key is.
///
/// The key types vodozemac builds from raw bytes take `&[u8; 32]`, and the ones
/// which parse base64 themselves do their own length checking. This is for the
/// former, so that a short string is refused by name rather than panicking.
fn secret32(label: &str, encoded: &str) -> Result<[u8; 32], Error> {
    let bytes = base64_decode(encoded).map_err(rt_err)?;

    key32(label, &bytes)
}

// --- Account ---------------------------------------------------------------

#[magnus::wrap(class = "Vodozemac::Account", free_immediately, size)]
struct Account(RefCell<OlmAccount>);

impl Account {
    fn new() -> Self {
        Account(RefCell::new(OlmAccount::new()))
    }

    fn from_pickle(pickle: String, pickle_key: String) -> Result<Self, Error> {
        let key = key32("pickle_key", pickle_key.as_bytes())?;
        let p = AccountPickle::from_encrypted(&pickle, &key).map_err(rt_err)?;
        Ok(Account(RefCell::new(OlmAccount::from_pickle(p))))
    }

    fn pickle(&self, pickle_key: String) -> Result<String, Error> {
        let key = key32("pickle_key", pickle_key.as_bytes())?;
        Ok(self.0.borrow().pickle().encrypt(&key))
    }

    fn ed25519_key(&self) -> String {
        self.0.borrow().ed25519_key().to_base64()
    }

    fn curve25519_key(&self) -> String {
        self.0.borrow().curve25519_key().to_base64()
    }

    fn sign(&self, message: String) -> String {
        self.0.borrow().sign(message.as_bytes()).to_base64()
    }

    fn one_time_keys(&self) -> HashMap<String, String> {
        self.0
            .borrow()
            .one_time_keys()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect()
    }

    fn max_number_of_one_time_keys(&self) -> usize {
        self.0.borrow().max_number_of_one_time_keys()
    }

    /// How many one-time keys this account is holding, published or not.
    fn stored_one_time_key_count(&self) -> usize {
        self.0.borrow().stored_one_time_key_count()
    }

    fn generate_one_time_keys(&self, count: usize) {
        self.0.borrow_mut().generate_one_time_keys(count);
    }


    fn fallback_key(&self) -> HashMap<String, String> {
        self.0
            .borrow()
            .fallback_key()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect()
    }

    fn generate_fallback_key(&self) {
        self.0.borrow_mut().generate_fallback_key();
    }

    fn mark_keys_as_published(&self) {
        self.0.borrow_mut().mark_keys_as_published();
    }

    /// Drops the private half of the previous fallback key.
    ///
    /// The spec says to keep at most two fallback private keys — the current one
    /// and the one before it — and to drop the older once it is reasonably
    /// certain no more messages will arrive using it, because a fallback key is
    /// not consumed by use and so keeps decrypting replays indefinitely.
    /// Returns whether there was one to forget.
    fn forget_fallback_key(&self) -> bool {
        self.0.borrow_mut().forget_fallback_key()
    }

    /// Returns a Session for sending to a peer identified by their identity and
    /// one-time keys (both base64).
    fn create_outbound_session(
        &self,
        identity_key: String,
        one_time_key: String,
    ) -> Result<Session, Error> {
        let ik = Curve25519Public::from_base64(&identity_key).map_err(rt_err)?;
        let otk = Curve25519Public::from_base64(&one_time_key).map_err(rt_err)?;
        let session = self
            .0
            .borrow()
            .create_outbound_session(OlmSessionConfig::version_1(), ik, otk)
            .map_err(rt_err)?;
        Ok(Session(RefCell::new(session)))
    }

    /// Establishes an inbound Session from a received pre-key message (base64
    /// body, as carried in an m.room.encrypted olm `body`). Returns
    /// `[session, plaintext]`.
    fn create_inbound_session(
        &self,
        identity_key: String,
        prekey_message_body: String,
    ) -> Result<(Session, String), Error> {
        let ik = Curve25519Public::from_base64(&identity_key).map_err(rt_err)?;
        let prekey = PreKeyMessage::from_base64(&prekey_message_body).map_err(rt_err)?;
        let result = self
            .0
            .borrow_mut()
            .create_inbound_session(OlmSessionConfig::version_1(), ik, &prekey)
            .map_err(rt_err)?;
        let plaintext = String::from_utf8(result.plaintext).map_err(rt_err)?;
        Ok((Session(RefCell::new(result.session)), plaintext))
    }
}

// --- Session (Olm 1:1) -----------------------------------------------------

#[magnus::wrap(class = "Vodozemac::Session", free_immediately, size)]
struct Session(RefCell<OlmSession>);

impl Session {
    fn session_id(&self) -> String {
        self.0.borrow().session_id()
    }

    /// Whether this session has ever decrypted a message from the other side.
    ///
    /// Until it has, every message it encrypts is a pre-key message, because the
    /// peer may not have the session yet. This is what says which.
    fn has_received_message(&self) -> bool {
        self.0.borrow().has_received_message()
    }

    fn pickle(&self, pickle_key: String) -> Result<String, Error> {
        let key = key32("pickle_key", pickle_key.as_bytes())?;
        Ok(self.0.borrow().pickle().encrypt(&key))
    }

    fn from_pickle(pickle: String, pickle_key: String) -> Result<Self, Error> {
        let key = key32("pickle_key", pickle_key.as_bytes())?;
        let p = SessionPickle::from_encrypted(&pickle, &key).map_err(rt_err)?;
        Ok(Session(RefCell::new(OlmSession::from_pickle(p))))
    }

    /// Encrypts plaintext; returns `[message_type, body_base64]` matching the
    /// Matrix olm ciphertext shape.
    fn encrypt(&self, plaintext: String) -> Result<(usize, String), Error> {
        let message = self.0.borrow_mut().encrypt(plaintext.as_bytes()).map_err(rt_err)?;
        let (mtype, ciphertext) = message.to_parts();
        Ok((mtype, base64_encode(ciphertext)))
    }

    /// Decrypts an olm message given its type (0 = pre-key, 1 = normal) and
    /// base64 body.
    fn decrypt(&self, message_type: usize, body: String) -> Result<String, Error> {
        let ciphertext = base64_decode(&body).map_err(rt_err)?;
        let message = OlmMessage::from_parts(message_type, &ciphertext).map_err(rt_err)?;
        let plaintext = self.0.borrow_mut().decrypt(&message).map_err(rt_err)?;
        String::from_utf8(plaintext).map_err(rt_err)
    }
}

// --- GroupSession (Megolm outbound) ---------------------------------------

#[magnus::wrap(class = "Vodozemac::GroupSession", free_immediately, size)]
struct GroupSession(RefCell<MegolmGroupSession>);

impl GroupSession {
    fn new() -> Self {
        GroupSession(RefCell::new(MegolmGroupSession::new(MegolmSessionConfig::version_1())))
    }

    fn session_id(&self) -> String {
        self.0.borrow().session_id()
    }

    fn message_index(&self) -> u32 {
        self.0.borrow().message_index()
    }

    /// The session key (base64) to share with recipients via m.room_key.
    fn session_key(&self) -> String {
        self.0.borrow().session_key().to_base64()
    }

    /// Encrypts plaintext, returning the megolm message as base64.
    fn encrypt(&self, plaintext: String) -> String {
        self.0.borrow_mut().encrypt(plaintext.as_bytes()).to_base64()
    }

    fn pickle(&self, pickle_key: String) -> Result<String, Error> {
        let key = key32("pickle_key", pickle_key.as_bytes())?;
        Ok(self.0.borrow().pickle().encrypt(&key))
    }

    fn from_pickle(pickle: String, pickle_key: String) -> Result<Self, Error> {
        let key = key32("pickle_key", pickle_key.as_bytes())?;
        let p = GroupSessionPickle::from_encrypted(&pickle, &key).map_err(rt_err)?;
        Ok(GroupSession(RefCell::new(MegolmGroupSession::from_pickle(p))))
    }
}

// --- InboundGroupSession (Megolm inbound) ---------------------------------

#[magnus::wrap(class = "Vodozemac::InboundGroupSession", free_immediately, size)]
struct InboundGroupSession(RefCell<MegolmInbound>);

impl InboundGroupSession {
    /// Build from a base64 session key received in an m.room_key event.
    fn new(session_key: String) -> Result<Self, Error> {
        let key = SessionKey::from_base64(&session_key).map_err(rt_err)?;
        Ok(InboundGroupSession(RefCell::new(MegolmInbound::new(
            &key,
            MegolmSessionConfig::version_1(),
        ))))
    }

    /// Build from a base64 **exported** session key.
    ///
    /// This is the format room keys travel in outside of `m.room_key`: server-side
    /// key backup (`m.megolm_backup.v1.curve25519-aes-sha2`) and
    /// `m.forwarded_room_key` both carry an `ExportedSessionKey`, which is
    /// version 1 and carries no signature — so `new` (which requires a signed
    /// version 2 `SessionKey`) cannot accept them. Without this, a client can
    /// never read history it did not receive a live `m.room_key` for.
    ///
    /// The resulting session is NOT signature-verified, because an exported key
    /// has no signature to verify. That is inherent to the format: the sender
    /// identity of such a session is only as trustworthy as whoever handed it
    /// over, which is why the spec treats backup-restored keys as unverified.
    fn import(exported_key: String) -> Result<Self, Error> {
        let key = ExportedSessionKey::from_base64(&exported_key).map_err(rt_err)?;
        Ok(InboundGroupSession(RefCell::new(MegolmInbound::import(
            &key,
            MegolmSessionConfig::version_1(),
        ))))
    }

    fn session_id(&self) -> String {
        self.0.borrow().session_id()
    }

    fn first_known_index(&self) -> u32 {
        self.0.borrow().first_known_index()
    }

    /// Whether the two sessions are the same megolm session, by their ratchets.
    ///
    /// Two copies of one session may have been received separately — one live,
    /// one from backup — and reached different indices. This says they belong
    /// together without saying which is ahead.
    fn connected(&self, other: &InboundGroupSession) -> bool {
        self.0.borrow_mut().connected(&mut other.0.borrow_mut())
    }

    /// Which of the two sessions holds more of the ratchet.
    ///
    /// Returns one of `:equal`, `:better`, `:worse` or `:unconnected` — the last
    /// meaning they are not the same session at all. This is how a client
    /// decides whether a key it has just been handed is worth keeping over the
    /// one it already has.
    fn compare(&self, other: &InboundGroupSession) -> Result<magnus::Symbol, Error> {
        use vodozemac_core::megolm::SessionOrdering;

        let ruby = Ruby::get().map_err(rt_err)?;

        let name = match self.0.borrow_mut().compare(&mut other.0.borrow_mut()) {
            SessionOrdering::Equal => "equal",
            SessionOrdering::Better => "better",
            SessionOrdering::Worse => "worse",
            SessionOrdering::Unconnected => "unconnected",
        };

        Ok(ruby.to_symbol(name))
    }

    /// Move the ratchet forward to `index`, discarding the keys before it.
    ///
    /// Returns whether it moved. This is how a session is trimmed to the history
    /// a room's visibility rules allow a member to read.
    fn advance_to(&self, index: u32) -> bool {
        self.0.borrow_mut().advance_to(index)
    }

    /// Export this session at `index`, base64, for uploading to key backup or
    /// forwarding to another device. Returns nil when the ratchet has already
    /// moved past `index` and can no longer produce a key for it — megolm
    /// ratchets forward only, so an earlier index is unrecoverable by design.
    fn export_at(&self, index: u32) -> Option<String> {
        self.0.borrow_mut().export_at(index).map(|key| key.to_base64())
    }

    /// Export at the earliest index this session can still reach.
    fn export_at_first_known_index(&self) -> String {
        self.0.borrow().export_at_first_known_index().to_base64()
    }

    /// Decrypts a base64 megolm message; returns `[plaintext, message_index]`.
    fn decrypt(&self, message: String) -> Result<(String, u32), Error> {
        let msg = MegolmMessage::from_base64(&message).map_err(rt_err)?;
        let decrypted = self.0.borrow_mut().decrypt(&msg).map_err(rt_err)?;
        let plaintext = String::from_utf8(decrypted.plaintext).map_err(rt_err)?;
        Ok((plaintext, decrypted.message_index))
    }

    fn pickle(&self, pickle_key: String) -> Result<String, Error> {
        let key = key32("pickle_key", pickle_key.as_bytes())?;
        Ok(self.0.borrow().pickle().encrypt(&key))
    }

    fn from_pickle(pickle: String, pickle_key: String) -> Result<Self, Error> {
        let key = key32("pickle_key", pickle_key.as_bytes())?;
        let p = InboundGroupSessionPickle::from_encrypted(&pickle, &key).map_err(rt_err)?;
        Ok(InboundGroupSession(RefCell::new(MegolmInbound::from_pickle(p))))
    }
}

// --- Sas (short authentication string) -------------------------------------

/// One half of an SAS verification, before the Diffie-Hellman.
///
/// A `Sas` establishes exactly one shared secret and is consumed doing so,
/// which is why `diffie_hellman` takes it out of the cell: vodozemac models that
/// with an owned `self`, and a second attempt is a programming error rather than
/// something to be silently allowed.
#[magnus::wrap(class = "Vodozemac::Sas", free_immediately, size)]
struct Sas {
    sas: RefCell<Option<vodozemac_core::sas::Sas>>,
    // Kept separately so that it survives the Diffie-Hellman: the SAS and MAC
    // info strings are built from BOTH public keys, so a caller still needs its
    // own after the exchange has consumed the Sas itself.
    public_key: String,
}

impl Sas {
    fn new() -> Self {
        let sas = vodozemac_core::sas::Sas::new();
        let public_key = sas.public_key().to_base64();

        Sas {
            sas: RefCell::new(Some(sas)),
            public_key,
        }
    }

    /// The ephemeral public key to send in `m.key.verification.key`.
    fn public_key(&self) -> String {
        self.public_key.clone()
    }

    fn diffie_hellman(&self, their_public_key: String) -> Result<EstablishedSas, Error> {
        let key = Curve25519Public::from_base64(&their_public_key).map_err(rt_err)?;
        let sas = self
            .sas
            .borrow_mut()
            .take()
            .ok_or_else(|| rt_err("this Sas has already been established"))?;

        Ok(EstablishedSas {
            sas: sas.diffie_hellman(key).map_err(rt_err)?,
            our_public_key: self.public_key.clone(),
            // Re-encoded from the parsed key rather than kept as given, so that
            // the pair is canonical base64 on both sides: the info strings are
            // built by concatenating these, and must match byte for byte.
            their_public_key: key.to_base64(),
        })
    }
}

/// An established SAS channel, which carries both public keys.
///
/// vodozemac drops them at this point, but every info string the spec defines
/// is built from both, so carrying them here is what lets a caller construct
/// one without tracking the keys itself.
#[magnus::wrap(class = "Vodozemac::EstablishedSas", free_immediately, size)]
struct EstablishedSas {
    sas: vodozemac_core::sas::EstablishedSas,
    our_public_key: String,
    their_public_key: String,
}

impl EstablishedSas {
    /// Our own ephemeral public key, as sent in `m.key.verification.key`.
    fn our_public_key(&self) -> String {
        self.our_public_key.clone()
    }

    /// The other device's ephemeral public key, as received.
    fn their_public_key(&self) -> String {
        self.their_public_key.clone()
    }

    /// The three numbers of the `decimal` SAS method, already offset by 1000.
    ///
    /// This is the method to offer. Decimal is required of every client, so it
    /// always agrees, and MSC4405 deprecates the alternative.
    fn decimals(&self, info: String) -> (u16, u16, u16) {
        self.sas.bytes(&info).decimals()
    }

    /// The seven emoji indices of the `emoji` SAS method, as table offsets.
    ///
    /// Deprecated by MSC4405, because each client names the emoji in its own
    /// language and two users can therefore hold different words for the same
    /// picture. Kept so that a verification with a client which offers nothing
    /// else can still be shown.
    fn emoji_indices(&self, info: String) -> Vec<u8> {
        self.sas.bytes(&info).emoji_indices().to_vec()
    }

    /// The raw bytes, for a SAS method this crate does not implement.
    fn bytes(&self, info: String) -> Vec<u8> {
        self.sas.bytes(&info).as_bytes().to_vec()
    }

    /// As many raw bytes as a method asks for, rather than the six `bytes` gives.
    ///
    /// Refused above 8160 bytes, which is the most HKDF-SHA256 will expand to.
    fn bytes_raw(&self, info: String, count: usize) -> Result<Vec<u8>, Error> {
        self.sas.bytes_raw(&info, count).map_err(|_| {
            rt_err(format!("cannot expand {count} bytes of SAS material"))
        })
    }

    fn calculate_mac(&self, input: String, info: String) -> String {
        self.sas.calculate_mac(&input, &info).to_base64()
    }

    /// The `hkdf-hmac-sha256` MAC, which libolm encoded incorrectly.
    ///
    /// Deprecated by the spec in favour of `hkdf-hmac-sha256.v2`, and kept only
    /// so that a verification with an older client can still be read.
    fn calculate_mac_invalid_base64(&self, input: String, info: String) -> String {
        self.sas.calculate_mac_invalid_base64(&input, &info)
    }

    fn verify_mac(&self, input: String, info: String, tag: String) -> Result<bool, Error> {
        let mac = vodozemac_core::sas::Mac::from_base64(&tag).map_err(rt_err)?;
        Ok(self.sas.verify_mac(&input, &info, &mac).is_ok())
    }
}

// --- ed25519 ---------------------------------------------------------------

/// A long-term ed25519 signing key, which can be written down and read back.
///
/// This is the type a Matrix cross-signing key is: the private half goes into
/// secret storage as base64, and the public half names the key. `Ed25519Keypair`
/// is the faster one for signing in bulk, but it has no serialisation, so an
/// identity which has to survive a restart is this one.
#[magnus::wrap(class = "Vodozemac::Ed25519SecretKey", free_immediately, size)]
struct Ed25519SecretKey(Ed25519Secret);

impl Ed25519SecretKey {
    fn new() -> Self {
        Ed25519SecretKey(Ed25519Secret::new())
    }

    fn from_base64(encoded: String) -> Result<Self, Error> {
        Ok(Ed25519SecretKey(Ed25519Secret::from_base64(&encoded).map_err(rt_err)?))
    }

    /// The private half, base64. This belongs in secret storage and nowhere else.
    fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    /// The public half, base64, which is also how the key is named.
    fn public_key(&self) -> String {
        self.0.public_key().to_base64()
    }

    /// Sign a message, returning the signature as base64.
    fn sign(&self, message: String) -> String {
        self.0.sign(message.as_bytes()).to_base64()
    }
}

/// An ephemeral ed25519 keypair, which signs faster and cannot be written down.
///
/// vodozemac keeps its pickle private, so there is no way to serialise one: this
/// is for a key which lives as long as the process does. An Account holds one of
/// these for its own device signature.
#[magnus::wrap(class = "Vodozemac::Ed25519Keypair", free_immediately, size)]
struct Ed25519Keypair(Ed25519Pair);

impl Ed25519Keypair {
    fn new() -> Self {
        Ed25519Keypair(Ed25519Pair::new())
    }

    /// The public half, base64, which is also how the key is named.
    fn public_key(&self) -> String {
        self.0.public_key().to_base64()
    }

    /// Sign a message, returning the signature as base64.
    fn sign(&self, message: String) -> String {
        self.0.sign(message.as_bytes()).to_base64()
    }
}

/// The public half of an ed25519 key, which is what a signature is checked against.
#[magnus::wrap(class = "Vodozemac::Ed25519PublicKey", free_immediately, size)]
struct Ed25519PublicKey(Ed25519Public);

impl Ed25519PublicKey {
    fn from_base64(encoded: String) -> Result<Self, Error> {
        Ok(Ed25519PublicKey(Ed25519Public::from_base64(&encoded).map_err(rt_err)?))
    }

    fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    /// Whether this key signed the message, given the base64 signature.
    fn verify(&self, message: String, signature: String) -> Result<bool, Error> {
        let sig = Ed25519Sig::from_base64(&signature).map_err(rt_err)?;

        Ok(self.0.verify(message.as_bytes(), &sig).is_ok())
    }
}

/// An ed25519 signature, for the caller which wants one parsed before sending it.
///
/// Every method here takes and returns a signature as base64, because that is
/// how Matrix carries one. This is the type for checking that a string is a
/// well-formed signature at all.
#[magnus::wrap(class = "Vodozemac::Ed25519Signature", free_immediately, size)]
struct Ed25519Signature(Ed25519Sig);

impl Ed25519Signature {
    fn from_base64(encoded: String) -> Result<Self, Error> {
        Ok(Ed25519Signature(Ed25519Sig::from_base64(&encoded).map_err(rt_err)?))
    }

    fn to_base64(&self) -> String {
        self.0.to_base64()
    }
}

// --- curve25519 ------------------------------------------------------------

/// The private half of a curve25519 key, which agrees a secret with a public one.
#[magnus::wrap(class = "Vodozemac::Curve25519SecretKey", free_immediately, size)]
struct Curve25519SecretKey(Curve25519Secret);

impl Curve25519SecretKey {
    fn new() -> Self {
        Curve25519SecretKey(Curve25519Secret::new())
    }

    fn from_base64(encoded: String) -> Result<Self, Error> {
        let bytes = secret32("secret key", &encoded)?;

        Ok(Curve25519SecretKey(Curve25519Secret::from_slice(&bytes)))
    }

    fn to_base64(&self) -> String {
        base64_encode(self.0.to_bytes().as_slice())
    }

    fn public_key(&self) -> String {
        Curve25519Public::from(&self.0).to_base64()
    }

    /// The raw shared secret with another key, base64.
    ///
    /// Nothing in Matrix wants this: Sas and PkEncryption do their own exchange
    /// and derive from it. It is bound because vodozemac exposes it, and a raw
    /// secret which has not been through a KDF is not a key — derive one before
    /// it encrypts anything. Nil when the peer's key is non-contributory.
    fn diffie_hellman(&self, their_public_key: String) -> Result<Option<String>, Error> {
        let key = Curve25519Public::from_base64(&their_public_key).map_err(rt_err)?;

        Ok(self.0.diffie_hellman(&key).map(|shared| base64_encode(shared.as_bytes())))
    }
}

/// The public half of a curve25519 key, which is how a device is addressed.
#[magnus::wrap(class = "Vodozemac::Curve25519PublicKey", free_immediately, size)]
struct Curve25519PublicKey(Curve25519Public);

impl Curve25519PublicKey {
    fn from_base64(encoded: String) -> Result<Self, Error> {
        Ok(Curve25519PublicKey(Curve25519Public::from_base64(&encoded).map_err(rt_err)?))
    }

    fn to_base64(&self) -> String {
        self.0.to_base64()
    }
}

// --- PkEncryption / PkDecryption -------------------------------------------

/// The private half of a PkEncryption key, which reads what was sealed to it.
///
/// This is libolm's PkDecryption, which is the primitive Matrix server-side key
/// backup is built on: `m.megolm_backup.v1.curve25519-aes-sha2` is an ECDH to
/// this key, HKDF-SHA256, AES-256-CBC and a truncated HMAC.
///
/// The MAC authenticates nothing — libolm computed it over the empty string
/// rather than the ciphertext, and every implementation has reproduced the bug
/// ever since for compatibility. So a message which verifies has only been shown
/// to come from somebody who knew the public key, which is everybody. See the
/// warning in the specification, and MSC4048 for the version which fixes it.
#[magnus::wrap(class = "Vodozemac::PkDecryption", free_immediately, size)]
struct PkDecryption(PkDecrypt);

impl PkDecryption {
    fn new() -> Self {
        PkDecryption(PkDecrypt::new())
    }

    /// The key a stored private half describes, which is how a backup is reopened.
    fn from_base64(secret_key: String) -> Result<Self, Error> {
        let bytes = secret32("secret key", &secret_key)?;

        Ok(PkDecryption(PkDecrypt::from_key(Curve25519Secret::from_slice(&bytes))))
    }

    /// The public half, base64, which anybody may seal to.
    fn public_key(&self) -> String {
        self.0.public_key().to_base64()
    }

    /// The private half, base64, which belongs in secret storage and nowhere else.
    fn secret_key(&self) -> String {
        base64_encode(self.0.secret_key().to_bytes().as_slice())
    }

    /// Open a message, given its three base64 parts as the specification names them.
    fn decrypt(
        &self,
        ciphertext: String,
        mac: String,
        ephemeral_key: String,
    ) -> Result<String, Error> {
        let message = PkMessage::from_base64(&ciphertext, &mac, &ephemeral_key).map_err(rt_err)?;
        let plaintext = self.0.decrypt(&message).map_err(rt_err)?;

        String::from_utf8(plaintext).map_err(rt_err)
    }
}

/// The public half of a PkEncryption key, which seals to it.
///
/// Holding this is enough to add to a backup and not enough to read one, which
/// is what lets a device upload history it cannot itself recover.
#[magnus::wrap(class = "Vodozemac::PkEncryption", free_immediately, size)]
struct PkEncryption(PkEncrypt);

impl PkEncryption {
    fn from_base64(public_key: String) -> Result<Self, Error> {
        let key = Curve25519Public::from_base64(&public_key).map_err(rt_err)?;

        Ok(PkEncryption(PkEncrypt::from_key(key)))
    }

    /// Seal a message; returns `[ciphertext, mac, ephemeral_key]`, each base64.
    fn encrypt(&self, plaintext: String) -> Result<(String, String, String), Error> {
        let message = self.0.encrypt(plaintext.as_bytes()).map_err(rt_err)?;

        Ok((
            base64_encode(&message.ciphertext),
            base64_encode(&message.mac),
            message.ephemeral_key.to_base64(),
        ))
    }
}

// --- module-level functions ------------------------------------------------

/// Verify an ed25519 signature. `key` and `signature` are base64; returns bool.
fn verify_signature(key: String, message: String, signature: String) -> Result<bool, Error> {
    let public_key = Ed25519Public::from_base64(&key).map_err(rt_err)?;
    let sig = Ed25519Sig::from_base64(&signature).map_err(rt_err)?;
    Ok(public_key.verify(message.as_bytes(), &sig).is_ok())
}

// --- init ------------------------------------------------------------------

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let namespace = ruby.define_module("Vodozemac")?;

    // Which vodozemac this was built against, as against Vodozemac::VERSION, which is the gem's.
    namespace.const_set("NATIVE_VERSION", vodozemac_core::VERSION)?;

    let account = namespace.define_class("Account", ruby.class_object())?;
    account.define_singleton_method("new", function!(Account::new, 0))?;
    account.define_singleton_method("from_pickle", function!(Account::from_pickle, 2))?;
    account.define_method("pickle", method!(Account::pickle, 1))?;
    account.define_method("ed25519_key", method!(Account::ed25519_key, 0))?;
    account.define_method("curve25519_key", method!(Account::curve25519_key, 0))?;
    account.define_method("sign", method!(Account::sign, 1))?;
    account.define_method("one_time_keys", method!(Account::one_time_keys, 0))?;
    account.define_method(
        "max_number_of_one_time_keys",
        method!(Account::max_number_of_one_time_keys, 0),
    )?;
    account.define_method(
        "stored_one_time_key_count",
        method!(Account::stored_one_time_key_count, 0),
    )?;
    account.define_method("generate_one_time_keys", method!(Account::generate_one_time_keys, 1))?;
    account.define_method("fallback_key", method!(Account::fallback_key, 0))?;
    account.define_method("generate_fallback_key", method!(Account::generate_fallback_key, 0))?;
    account.define_method("mark_keys_as_published", method!(Account::mark_keys_as_published, 0))?;
    account.define_method("forget_fallback_key", method!(Account::forget_fallback_key, 0))?;
    account.define_method("create_outbound_session", method!(Account::create_outbound_session, 2))?;
    account.define_method("create_inbound_session", method!(Account::create_inbound_session, 2))?;

    let session = namespace.define_class("Session", ruby.class_object())?;
    session.define_singleton_method("from_pickle", function!(Session::from_pickle, 2))?;
    session.define_method("session_id", method!(Session::session_id, 0))?;
    session.define_method("has_received_message", method!(Session::has_received_message, 0))?;
    session.define_method("pickle", method!(Session::pickle, 1))?;
    session.define_method("encrypt", method!(Session::encrypt, 1))?;
    session.define_method("decrypt", method!(Session::decrypt, 2))?;

    let group = namespace.define_class("GroupSession", ruby.class_object())?;
    group.define_singleton_method("new", function!(GroupSession::new, 0))?;
    group.define_singleton_method("from_pickle", function!(GroupSession::from_pickle, 2))?;
    group.define_method("session_id", method!(GroupSession::session_id, 0))?;
    group.define_method("message_index", method!(GroupSession::message_index, 0))?;
    group.define_method("session_key", method!(GroupSession::session_key, 0))?;
    group.define_method("encrypt", method!(GroupSession::encrypt, 1))?;
    group.define_method("pickle", method!(GroupSession::pickle, 1))?;

    let inbound = namespace.define_class("InboundGroupSession", ruby.class_object())?;
    inbound.define_singleton_method("new", function!(InboundGroupSession::new, 1))?;
    inbound.define_singleton_method("import", function!(InboundGroupSession::import, 1))?;
    inbound.define_singleton_method("from_pickle", function!(InboundGroupSession::from_pickle, 2))?;
    inbound.define_method("session_id", method!(InboundGroupSession::session_id, 0))?;
    inbound.define_method("first_known_index", method!(InboundGroupSession::first_known_index, 0))?;
    inbound.define_method("connected", method!(InboundGroupSession::connected, 1))?;
    inbound.define_method("compare", method!(InboundGroupSession::compare, 1))?;
    inbound.define_method("advance_to", method!(InboundGroupSession::advance_to, 1))?;
    inbound.define_method("decrypt", method!(InboundGroupSession::decrypt, 1))?;
    inbound.define_method("pickle", method!(InboundGroupSession::pickle, 1))?;
    inbound.define_method("export_at", method!(InboundGroupSession::export_at, 1))?;
    inbound.define_method(
        "export_at_first_known_index",
        method!(InboundGroupSession::export_at_first_known_index, 0),
    )?;

    let sas = namespace.define_class("Sas", ruby.class_object())?;
    sas.define_singleton_method("new", function!(Sas::new, 0))?;
    sas.define_method("public_key", method!(Sas::public_key, 0))?;
    sas.define_method("diffie_hellman", method!(Sas::diffie_hellman, 1))?;

    let established = namespace.define_class("EstablishedSas", ruby.class_object())?;
    established.define_method("our_public_key", method!(EstablishedSas::our_public_key, 0))?;
    established.define_method("their_public_key", method!(EstablishedSas::their_public_key, 0))?;
    established.define_method("emoji_indices", method!(EstablishedSas::emoji_indices, 1))?;
    established.define_method("decimals", method!(EstablishedSas::decimals, 1))?;
    established.define_method("bytes", method!(EstablishedSas::bytes, 1))?;
    established.define_method("bytes_raw", method!(EstablishedSas::bytes_raw, 2))?;
    established.define_method("calculate_mac", method!(EstablishedSas::calculate_mac, 2))?;
    established.define_method(
        "calculate_mac_invalid_base64",
        method!(EstablishedSas::calculate_mac_invalid_base64, 2),
    )?;
    established.define_method("verify_mac", method!(EstablishedSas::verify_mac, 3))?;

    let secret = namespace.define_class("Ed25519SecretKey", ruby.class_object())?;
    secret.define_singleton_method("new", function!(Ed25519SecretKey::new, 0))?;
    secret.define_singleton_method("from_base64", function!(Ed25519SecretKey::from_base64, 1))?;
    secret.define_method("to_base64", method!(Ed25519SecretKey::to_base64, 0))?;
    secret.define_method("public_key", method!(Ed25519SecretKey::public_key, 0))?;
    secret.define_method("sign", method!(Ed25519SecretKey::sign, 1))?;

    let keypair = namespace.define_class("Ed25519Keypair", ruby.class_object())?;
    keypair.define_singleton_method("new", function!(Ed25519Keypair::new, 0))?;
    keypair.define_method("public_key", method!(Ed25519Keypair::public_key, 0))?;
    keypair.define_method("sign", method!(Ed25519Keypair::sign, 1))?;

    let public = namespace.define_class("Ed25519PublicKey", ruby.class_object())?;
    public.define_singleton_method("from_base64", function!(Ed25519PublicKey::from_base64, 1))?;
    public.define_method("to_base64", method!(Ed25519PublicKey::to_base64, 0))?;
    public.define_method("verify", method!(Ed25519PublicKey::verify, 2))?;

    let signature = namespace.define_class("Ed25519Signature", ruby.class_object())?;
    signature.define_singleton_method("from_base64", function!(Ed25519Signature::from_base64, 1))?;
    signature.define_method("to_base64", method!(Ed25519Signature::to_base64, 0))?;

    let curve_secret = namespace.define_class("Curve25519SecretKey", ruby.class_object())?;
    curve_secret.define_singleton_method("new", function!(Curve25519SecretKey::new, 0))?;
    curve_secret
        .define_singleton_method("from_base64", function!(Curve25519SecretKey::from_base64, 1))?;
    curve_secret.define_method("to_base64", method!(Curve25519SecretKey::to_base64, 0))?;
    curve_secret.define_method("public_key", method!(Curve25519SecretKey::public_key, 0))?;
    curve_secret
        .define_method("diffie_hellman", method!(Curve25519SecretKey::diffie_hellman, 1))?;

    let curve_public = namespace.define_class("Curve25519PublicKey", ruby.class_object())?;
    curve_public
        .define_singleton_method("from_base64", function!(Curve25519PublicKey::from_base64, 1))?;
    curve_public.define_method("to_base64", method!(Curve25519PublicKey::to_base64, 0))?;

    let decryption = namespace.define_class("PkDecryption", ruby.class_object())?;
    decryption.define_singleton_method("new", function!(PkDecryption::new, 0))?;
    decryption.define_singleton_method("from_base64", function!(PkDecryption::from_base64, 1))?;
    decryption.define_method("public_key", method!(PkDecryption::public_key, 0))?;
    decryption.define_method("secret_key", method!(PkDecryption::secret_key, 0))?;
    decryption.define_method("decrypt", method!(PkDecryption::decrypt, 3))?;

    let encryption = namespace.define_class("PkEncryption", ruby.class_object())?;
    encryption.define_singleton_method("from_base64", function!(PkEncryption::from_base64, 1))?;
    encryption.define_method("encrypt", method!(PkEncryption::encrypt, 1))?;

    namespace.define_module_function("verify_signature", function!(verify_signature, 3))?;

    Ok(())
}
