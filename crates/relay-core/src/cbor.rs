//! Deterministic CBOR (RFC 8949 §4.2.1) restricted to the types the wire format uses: unsigned
//! integers, byte strings, text strings, maps, and arrays of text strings.
//!
//! Decoding goes through `ciborium`, then converts to [`Value`], rejecting anything outside
//! the subset, then re-encodes and requires the result to equal the input byte for byte. That
//! one comparison enforces shortest-form integers and lengths, definite lengths and key order.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// Largest message the core will decode (wire-format §1.2).
pub const MAX_MESSAGE_LEN: usize = 65_536;
/// Deepest map nesting allowed (wire-format §1.2).
pub const MAX_DEPTH: usize = 3;
/// Most items in one array (wire-format §1.2).
pub const MAX_ARRAY_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Map(BTreeMap<String, Value>),
    /// An array whose items are all text strings; the only array the wire format allows.
    TextArray(Vec<String>),
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as u64 {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_text(out: &mut Vec<u8>, s: &str) {
    head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn encode_into(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Uint(n) => head(out, 0, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => encode_text(out, s),
        Value::TextArray(items) => {
            head(out, 4, items.len() as u64);
            for t in items {
                encode_text(out, t);
            }
        }
        Value::Map(m) => {
            // Sort by the encoded key bytes (RFC 8949 §4.2.1), not by string order.
            let mut entries: Vec<(Vec<u8>, &Value)> = m
                .iter()
                .map(|(k, v)| {
                    let mut kb = Vec::with_capacity(k.len() + 2);
                    encode_text(&mut kb, k);
                    (kb, v)
                })
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            head(out, 5, entries.len() as u64);
            for (kb, v) in entries {
                out.extend_from_slice(&kb);
                encode_into(out, v);
            }
        }
    }
}

/// Deterministic encoding of `v`.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, v);
    out
}

fn convert(v: ciborium::Value, depth: usize) -> Result<Value> {
    use ciborium::Value as C;
    Ok(match v {
        C::Integer(i) => {
            let i: i128 = i.into();
            Value::Uint(
                u64::try_from(i)
                    .map_err(|_| Error::Decode("negative or oversized integer".into()))?,
            )
        }
        C::Bytes(b) => Value::Bytes(b),
        C::Text(t) => Value::Text(t),
        C::Map(entries) => {
            if depth >= MAX_DEPTH {
                return Err(Error::Decode("maps nested too deeply".into()));
            }
            let mut m = BTreeMap::new();
            for (k, v) in entries {
                let C::Text(k) = k else {
                    return Err(Error::Decode("map key is not a text string".into()));
                };
                let v = convert(v, depth + 1)?;
                if m.insert(k, v).is_some() {
                    return Err(Error::Decode("duplicate map key".into()));
                }
            }
            Value::Map(m)
        }
        C::Tag(..) => return Err(Error::Decode("CBOR tags are not allowed".into())),
        C::Float(_) => return Err(Error::Decode("floats are not allowed".into())),
        C::Bool(_) | C::Null => return Err(Error::Decode("simple values are not allowed".into())),
        C::Array(items) => {
            if items.len() > MAX_ARRAY_LEN {
                return Err(Error::Decode(format!(
                    "arrays hold at most {MAX_ARRAY_LEN} items"
                )));
            }
            let items = items
                .into_iter()
                .map(|i| match i {
                    C::Text(t) => Ok(t),
                    _ => Err(Error::Decode("array items must be text strings".into())),
                })
                .collect::<Result<Vec<_>>>()?;
            Value::TextArray(items)
        }
        _ => return Err(Error::Decode("unsupported CBOR item".into())),
    })
}

/// Strictly decode one deterministic-CBOR map. Rejects anything outside the wire subset,
/// trailing bytes and non-canonical encodings.
pub fn decode_map(bytes: &[u8]) -> Result<BTreeMap<String, Value>> {
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(Error::Decode("message too long".into()));
    }
    let mut reader = bytes;
    // Recursion limit well above MAX_DEPTH so ciborium itself cannot be driven deep.
    let raw: ciborium::Value = ciborium::de::from_reader_with_recursion_limit(&mut reader, 16)
        .map_err(|e| Error::Decode(format!("invalid CBOR: {e}")))?;
    if !reader.is_empty() {
        return Err(Error::Decode("trailing bytes after CBOR item".into()));
    }
    let v = convert(raw, 0)?;
    if encode(&v) != bytes {
        return Err(Error::Decode(
            "CBOR is not in deterministic encoding".into(),
        ));
    }
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(Error::Decode("top-level item is not a map".into())),
    }
}

/// Field-by-field extraction from a decoded map that fails on missing, mistyped or leftover
/// keys.
pub(crate) struct Fields {
    map: BTreeMap<String, Value>,
}

impl Fields {
    pub fn new(map: BTreeMap<String, Value>) -> Self {
        Fields { map }
    }

    fn take(&mut self, key: &str) -> Result<Value> {
        self.map
            .remove(key)
            .ok_or_else(|| Error::Decode(format!("missing field `{key}`")))
    }

    pub fn uint(&mut self, key: &str) -> Result<u64> {
        match self.take(key)? {
            Value::Uint(n) => Ok(n),
            _ => Err(Error::Decode(format!(
                "field `{key}` is not an unsigned integer"
            ))),
        }
    }

    pub fn bytes(&mut self, key: &str) -> Result<Vec<u8>> {
        match self.take(key)? {
            Value::Bytes(b) => Ok(b),
            _ => Err(Error::Decode(format!("field `{key}` is not a byte string"))),
        }
    }

    pub fn fixed<const N: usize>(&mut self, key: &str) -> Result<[u8; N]> {
        let b = self.bytes(key)?;
        b.try_into()
            .map_err(|_| Error::Decode(format!("field `{key}` must be {N} bytes")))
    }

    pub fn text(&mut self, key: &str) -> Result<String> {
        match self.take(key)? {
            Value::Text(t) => Ok(t),
            _ => Err(Error::Decode(format!("field `{key}` is not a text string"))),
        }
    }

    pub fn text_array(&mut self, key: &str) -> Result<Vec<String>> {
        match self.take(key)? {
            Value::TextArray(a) => Ok(a),
            _ => Err(Error::Decode(format!(
                "field `{key}` is not an array of text strings"
            ))),
        }
    }

    pub fn map(&mut self, key: &str) -> Result<Fields> {
        match self.take(key)? {
            Value::Map(m) => Ok(Fields::new(m)),
            _ => Err(Error::Decode(format!("field `{key}` is not a map"))),
        }
    }

    pub fn opt_bytes(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        if self.map.contains_key(key) {
            self.bytes(key).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn opt_text(&mut self, key: &str) -> Result<Option<String>> {
        if self.map.contains_key(key) {
            self.text(key).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Require `v == 1`.
    pub fn version(&mut self) -> Result<()> {
        match self.uint("v")? {
            1 => Ok(()),
            v => Err(Error::Decode(format!("unsupported version v={v}"))),
        }
    }

    /// Fail if any key was not consumed.
    pub fn finish(self) -> Result<()> {
        match self.map.keys().next() {
            None => Ok(()),
            Some(k) => Err(Error::Decode(format!("unknown field `{k}`"))),
        }
    }
}

/// Builder for message maps.
#[derive(Default)]
pub(crate) struct MapBuilder(BTreeMap<String, Value>);

impl MapBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn uint(mut self, k: &str, v: u64) -> Self {
        self.0.insert(k.into(), Value::Uint(v));
        self
    }
    pub fn bytes(mut self, k: &str, v: &[u8]) -> Self {
        self.0.insert(k.into(), Value::Bytes(v.to_vec()));
        self
    }
    pub fn text(mut self, k: &str, v: &str) -> Self {
        self.0.insert(k.into(), Value::Text(v.into()));
        self
    }
    pub fn text_array(mut self, k: &str, v: &[String]) -> Self {
        self.0.insert(k.into(), Value::TextArray(v.to_vec()));
        self
    }
    pub fn map(mut self, k: &str, v: MapBuilder) -> Self {
        self.0.insert(k.into(), Value::Map(v.0));
        self
    }
    pub fn opt_bytes(self, k: &str, v: Option<&[u8]>) -> Self {
        match v {
            Some(v) => self.bytes(k, v),
            None => self,
        }
    }
    pub fn opt_text(self, k: &str, v: Option<&str>) -> Self {
        match v {
            Some(v) => self.text(k, v),
            None => self,
        }
    }
    pub fn encode(self) -> Vec<u8> {
        encode(&Value::Map(self.0))
    }
}

/// `context || 0x00 || cbor` (wire-format §1.3).
pub(crate) fn signed_bytes(context: &str, cbor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len() + 1 + cbor.len());
    out.extend_from_slice(context.as_bytes());
    out.push(0);
    out.extend_from_slice(cbor);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_order_is_length_first() {
        let b = MapBuilder::new()
            .uint("bb", 1)
            .uint("a", 2)
            .uint("ab", 3)
            .encode();
        // a, ab, bb
        assert_eq!(hex::encode(b), "a36161026261620362626201");
    }

    #[test]
    fn text_arrays_only() {
        // {"k": ["a", "b"]}
        let ok = hex::decode("a1616b8261616162").unwrap();
        let mut f = Fields::new(decode_map(&ok).unwrap());
        assert_eq!(f.text_array("k").unwrap(), vec!["a", "b"]);
        assert_eq!(
            MapBuilder::new()
                .text_array("k", &["a".into(), "b".into()])
                .encode(),
            ok
        );
        // An empty array, an array of integers, a nested array, an indefinite-length array.
        assert!(decode_map(&hex::decode("a1616b80").unwrap()).is_ok());
        for bad in ["a1616b820102", "a1616b81816161", "a1616b9f6161ff"] {
            assert!(decode_map(&hex::decode(bad).unwrap()).is_err(), "{bad}");
        }
        // More than 64 items.
        let mut long = hex::decode("a1616b9841").unwrap();
        long.extend(std::iter::repeat_n([0x61, 0x61], 65).flatten());
        assert!(decode_map(&long).is_err());
    }

    #[test]
    fn rejects_non_shortest_integer() {
        // {"v": 1} with 1 encoded as 0x18 0x01
        let bad = hex::decode("a161761801").unwrap();
        assert!(decode_map(&bad).is_err());
        assert!(decode_map(&hex::decode("a1617601").unwrap()).is_ok());
    }

    #[test]
    fn rejects_unsorted_keys() {
        // {"b": 1, "a": 2}
        assert!(decode_map(&hex::decode("a2616201616102").unwrap()).is_err());
    }

    #[test]
    fn rejects_indefinite_length() {
        // {_ "v": 1}
        assert!(decode_map(&hex::decode("bf617601ff").unwrap()).is_err());
    }

    #[test]
    fn rejects_duplicates_tags_floats_bools_int_arrays_trailing() {
        for h in [
            "a26176016176 02", // duplicate key
            "a16176c101",      // tag
            "a16176f93c00",    // float16
            "a16176f5",        // true
            "a161768101",      // array of integers
            "a161760100",      // trailing byte
            "a1617620",        // negative int
        ] {
            let b = hex::decode(h.replace(' ', "")).unwrap();
            assert!(decode_map(&b).is_err(), "{h}");
        }
    }

    #[test]
    fn rejects_deep_nesting() {
        // {"a": {"a": {"a": {}}}} : 4 maps
        assert!(decode_map(&hex::decode("a16161a16161a16161a0").unwrap()).is_err());
        assert!(decode_map(&hex::decode("a16161a16161a0").unwrap()).is_ok());
    }
}
