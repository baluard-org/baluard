//! Canonical CBOR for CTAP2 (RFC 8949 §4.2 canonical form).
//!
//! Encoding is canonical: shortest-length integers, definite lengths, and map
//! keys sorted by their encoded byte representation. CTAP2 requests must be
//! canonical (authenticators hash/compare whole messages), so maps are sorted
//! here and callers never hand-roll key order.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Unsigned(u64),
    Negative(i64),
    ByteString(Vec<u8>),
    TextString(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Null,
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError;

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= u64::from(u8::MAX) {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encoded_len_head(len: usize) -> usize {
    if len < 24 {
        1
    } else if len <= u8::MAX as usize {
        2
    } else if len <= u16::MAX as usize {
        3
    } else if len <= u32::MAX as usize {
        5
    } else {
        9
    }
}

impl Value {
    /// Encoded size of a key, used for canonical map ordering.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Unsigned(v) => write_head(out, 0, *v),
            Value::Negative(v) => {
                write_head(out, 1, (-1 - *v) as u64);
            }
            Value::ByteString(b) => {
                write_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::TextString(t) => {
                write_head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Value::Array(items) => {
                write_head(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out);
                }
            }
            Value::Map(pairs) => {
                write_head(out, 5, pairs.len() as u64);
                // Canonical order: sort by the encoded key bytes (RFC 8949
                // §4.2.1 length-first rule is subsumed by bytewise comparison
                // for these value shapes).
                let mut encoded: Vec<(Vec<u8>, &Value)> =
                    pairs.iter().map(|(k, v)| (k.encode(), v)).collect();
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    v.encode_into(out);
                }
            }
            Value::Null => out.push(0xf6),
            Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        }
    }

    /// H8: CTAP2 structures nest about 5 deep; anything deeper is hostile
    /// (a stack overflow is an abort, which panic catchers cannot stop),
    /// so the decoder refuses beyond this recursion depth.
    pub const MAX_DEPTH: u32 = 16;

    pub fn decode(bytes: &[u8]) -> Result<(Value, &[u8]), DecodeError> {
        Self::decode_at(bytes, 0)
    }

    fn decode_at(bytes: &[u8], depth: u32) -> Result<(Value, &[u8]), DecodeError> {
        if depth > Self::MAX_DEPTH {
            return Err(DecodeError);
        }
        let (&first, rest) = bytes.split_first().ok_or(DecodeError)?;
        let major = first >> 5;
        let info = first & 0x1f;
        let arg = match info {
            0..=23 => u64::from(info),
            24 => u64::from(*rest.first().ok_or(DecodeError)?),
            25 => {
                let v = rest.get(0..2).ok_or(DecodeError)?;
                u64::from(u16::from_be_bytes([v[0], v[1]]))
            }
            26 => {
                let v = rest.get(0..4).ok_or(DecodeError)?;
                u64::from(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            }
            27 => {
                let v = rest.get(0..8).ok_or(DecodeError)?;
                u64::from_be_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])
            }
            31 => return Err(DecodeError), // indefinite lengths: not in CTAP2
            _ => return Err(DecodeError),
        };
        let rest = match info {
            0..=23 => rest,
            24 => &rest[1..],
            25 => &rest[2..],
            26 => &rest[4..],
            27 => &rest[8..],
            _ => unreachable!(),
        };
        fn take<'a>(n: usize, rest: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), DecodeError> {
            if rest.len() < n {
                return Err(DecodeError);
            }
            Ok(rest.split_at(n))
        }
        match major {
            0 => Ok((Value::Unsigned(arg), rest)),
            1 => Ok((Value::Negative(-1 - (arg as i64)), rest)),
            2 => {
                let (data, rest) = take(arg as usize, rest)?;
                Ok((Value::ByteString(data.to_vec()), rest))
            }
            3 => {
                let (data, rest) = take(arg as usize, rest)?;
                let text = std::str::from_utf8(data).map_err(|_| DecodeError)?;
                Ok((Value::TextString(text.to_string()), rest))
            }
            4 => {
                let mut items = Vec::new();
                let mut rest = rest;
                for _ in 0..arg {
                    let (item, r) = Value::decode_at(rest, depth + 1)?;
                    items.push(item);
                    rest = r;
                }
                Ok((Value::Array(items), rest))
            }
            5 => {
                let mut pairs = Vec::new();
                let mut rest = rest;
                for _ in 0..arg {
                    let (k, r) = Value::decode_at(rest, depth + 1)?;
                    let (v, r) = Value::decode_at(r, depth + 1)?;
                    pairs.push((k, v));
                    rest = r;
                }
                Ok((Value::Map(pairs), rest))
            }
            7 => match (info, arg) {
                (20, _) => Ok((Value::Bool(false), rest)),
                (21, _) => Ok((Value::Bool(true), rest)),
                (22, _) => Ok((Value::Null, rest)),
                _ => Err(DecodeError), // floats/tags: not in CTAP2
            },
            _ => Err(DecodeError),
        }
    }

    /// Text-keyed map lookup (CTAP2 extensions and options).
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs
                .iter()
                .find(|(k, _)| matches!(k, Value::TextString(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_unsigned(&self) -> Option<u64> {
        match self {
            Value::Unsigned(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::ByteString(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn get(&self, key: i64) -> Option<&Value> {
        let key = if key < 0 {
            Value::Negative(key)
        } else {
            Value::Unsigned(key as u64)
        };
        match self {
            Value::Map(pairs) => pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Value;

    // RFC 8949 Appendix A vectors that fall inside the CTAP2 subset.
    #[test]
    fn rfc_vectors_encode() {
        assert_eq!(Value::Unsigned(0).encode(), b"\x00");
        assert_eq!(Value::Unsigned(23).encode(), b"\x17");
        assert_eq!(Value::Unsigned(24).encode(), b"\x18\x18");
        assert_eq!(Value::Unsigned(25).encode(), b"\x18\x19");
        assert_eq!(Value::Unsigned(100).encode(), b"\x18\x64");
        assert_eq!(Value::Unsigned(1000).encode(), b"\x19\x03\xe8");
        assert_eq!(Value::Unsigned(1_000_000).encode(), b"\x1a\x00\x0f\x42\x40");
        assert_eq!(
            Value::Unsigned(4_611_686_018_427_387_904).encode(),
            b"\x1b\x40\x00\x00\x00\x00\x00\x00\x00"
        );
        assert_eq!(Value::Negative(-1).encode(), b"\x20");
        assert_eq!(Value::Negative(-10).encode(), b"\x29");
        assert_eq!(Value::Negative(-1000).encode(), b"\x39\x03\xe7");
        assert_eq!(Value::ByteString(b"1".to_vec()).encode(), b"\x41\x31");
        assert_eq!(
            Value::ByteString(b"IETF".to_vec()).encode(),
            b"\x44\x49\x45\x54\x46"
        );
        assert_eq!(
            Value::TextString("IETF".into()).encode(),
            b"\x64\x49\x45\x54\x46"
        );
        assert_eq!(Value::Bool(false).encode(), b"\xf4");
        assert_eq!(Value::Bool(true).encode(), b"\xf5");
        assert_eq!(Value::Null.encode(), b"\xf6");
        assert_eq!(Value::Array(vec![]).encode(), b"\x80");
        assert_eq!(
            Value::Array(vec![
                Value::Unsigned(1),
                Value::Unsigned(2),
                Value::Unsigned(3)
            ])
            .encode(),
            b"\x83\x01\x02\x03"
        );
    }

    #[test]
    fn maps_are_canonically_sorted_by_encoded_key() {
        let map = Value::Map(vec![
            (Value::Unsigned(2), Value::Unsigned(20)),
            (Value::Unsigned(1), Value::Unsigned(10)),
            (Value::Unsigned(10), Value::Unsigned(100)),
        ]);
        // Keys 1, 2, 10 encode as 01, 02, 0a: bytewise order equals numeric here.
        assert_eq!(map.encode(), b"\xa3\x01\x0a\x02\x14\x0a\x18\x64");

        // RFC 8949 §4.2.1 canonical order for these keys is NOT numeric:
        // "aa" (10) sorts before "ff" via bytewise comparison of encodings.
        let map = Value::Map(vec![
            (Value::Unsigned(10), Value::Unsigned(1)),
            (Value::Unsigned(255), Value::Unsigned(2)),
        ]);
        assert_eq!(map.encode(), b"\xa2\x0a\x01\x18\xff\x02");
    }

    #[test]
    fn roundtrip_and_field_access() {
        let map = Value::Map(vec![
            (Value::Unsigned(1), Value::ByteString(vec![0xaa, 0xbb])),
            (
                Value::Unsigned(2),
                Value::Map(vec![(Value::Negative(-2), Value::TextString("rp".into()))]),
            ),
            (Value::Unsigned(3), Value::Array(vec![Value::Bool(true)])),
        ]);
        let encoded = map.encode();
        let (decoded, rest) = Value::decode(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, map);
        assert_eq!(decoded.get(1).unwrap().as_bytes().unwrap(), &[0xaa, 0xbb]);
        assert_eq!(
            decoded.get(2).unwrap().get(-2).unwrap(),
            &Value::TextString("rp".into())
        );
        assert_eq!(decoded.get(3).unwrap().as_array().unwrap().len(), 1);
    }

    #[test]
    fn rejects_indefinite_and_truncated() {
        assert!(Value::decode(b"\x5f\x41\x31\xff").is_err()); // indefinite byte string
        assert!(Value::decode(b"\x45\x01\x02\x03").is_err()); // truncated
        assert!(Value::decode(b"").is_err());
    }

    /// H8: recursion depth. A hostile device (malicious USB HID stack or
    /// NFC-emulating phone) sends nested arrays; a stack overflow is an
    /// abort, which panic catchers cannot intercept.
    #[test]
    fn nesting_at_the_depth_limit_still_decodes() {
        // 16 nested arrays with a terminal unsigned: the innermost child
        // lands exactly at depth 16 and is accepted.
        let mut bomb = vec![0x01u8];
        for _ in 0..16 {
            bomb.insert(0, 0x81);
        }
        assert!(Value::decode(&bomb).is_ok());
    }

    #[test]
    fn depth_bomb_beyond_the_limit_is_refused() {
        // 17 nested arrays: one past the limit.
        let mut bomb = vec![0x01u8];
        for _ in 0..17 {
            bomb.insert(0, 0x81);
        }
        assert!(Value::decode(&bomb).is_err());
    }

    #[test]
    fn max_ctap_message_depth_bomb_is_refused() {
        // 7609 nested 0x81 = one maximum CTAPHID message. On the 2 MiB
        // threads mobile runtimes spawn this overflows the stack before
        // the limit existed; it must decode as a plain error instead.
        let bomb = vec![0x81u8; 7609];
        assert!(Value::decode(&bomb).is_err());
    }

    #[test]
    fn depth_bombs_through_maps_are_refused() {
        // Map values, map keys, and mixed nesting share the depth counter
        // with the array arm.
        let mut map_values = vec![0x01u8];
        for _ in 0..17 {
            map_values.insert(0, 0x01); // key: unsigned 1
            map_values.insert(0, 0xa1); // map with one pair
        }
        assert!(Value::decode(&map_values).is_err());

        // A container used as a MAP KEY recurses through the same arm.
        let mut key_bomb = vec![0x01u8];
        for _ in 0..17 {
            key_bomb.insert(0, 0x81);
        }
        let mut key_bomb_map = key_bomb;
        key_bomb_map.push(0x01); // value
        key_bomb_map.insert(0, 0xa1);
        assert!(Value::decode(&key_bomb_map).is_err());

        // Mixed array/map alternation at the boundary: 16 deep decodes.
        let mut mixed = vec![0x01u8];
        for level in 0..16 {
            if level % 2 == 0 {
                mixed.insert(0, 0x81);
            } else {
                mixed.insert(0, 0x01);
                mixed.insert(0, 0xa1);
            }
        }
        assert!(Value::decode(&mixed).is_ok());
    }
}
