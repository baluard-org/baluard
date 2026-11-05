//! The daemon wire format for cipher objects: JSON with both the nested
//! `kind` and flat top-level fields. Shared by the daemon IPC handlers and
//! the CLI's `--direct` mode so the two cannot drift apart.

use crate::types::Cipher;

/// Strip passkey private key material from the nested kind JSON. Flat
/// top-level fields keep their values; the desktop reads both shapes.
fn redact_kind_secrets(mut kind: serde_json::Value) -> serde_json::Value {
    if let Some(creds) = kind
        .get_mut("data")
        .and_then(|d| d.get_mut("fido2_credentials"))
        .and_then(|v| v.as_array_mut())
    {
        for cred in creds {
            if let Some(obj) = cred.as_object_mut() {
                obj.remove("private_key");
                obj.remove("prf_key");
            }
        }
    }
    kind
}

pub fn cipher_to_json(c: &Cipher) -> serde_json::Value {
    let mut json = serde_json::json!({
        "id": c.id.to_string(),
        "name": c.name,
        "type": serde_json::to_value(c.kind.cipher_type()).unwrap_or(serde_json::Value::Null),
        "favorite": c.favorite,
        "reprompt": c.reprompt,
        "notes": c.notes,
        "tier": format!("{:?}", c.tier),
        "epoch": c.key_epoch,
        "seq": c.update_seq,
        "folder_id": c.folder_id,
        "tags": c.tags,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
        "password_history": c.password_history,
        "attachments": c.attachments,
        "custom_fields": c.custom_fields,
    });
    json["kind"] =
        redact_kind_secrets(serde_json::to_value(&c.kind).unwrap_or(serde_json::Value::Null));
    match &c.kind {
        crate::types::CipherKind::Login(data) => {
            json["username"] = serde_json::json!(data.username);
            json["password"] = serde_json::json!(data.password);
            json["uris"] = serde_json::json!(data.uris);
            json["totp"] = serde_json::json!(data.totp_uri);
            if let Some(ref fav) = data.favicon {
                json["favicon"] = serde_json::to_value(fav).unwrap_or(serde_json::Value::Null);
            }
            if let Some(ref fido2_list) = data.fido2_credentials {
                if !fido2_list.is_empty() {
                    json["fido2_credentials"] = serde_json::json!(
                        fido2_list
                            .iter()
                            .map(|pk| serde_json::json!({
                                "credential_id": pk.credential_id,
                                "rp_id": pk.rp_id,
                                "rp_name": pk.rp_name,
                                "user_name": pk.user_name,
                                "name": pk.name,
                                "counter": pk.counter,
                                "creation_date": pk.creation_date,
                                "private_key_missing": pk.private_key_missing,
                            }))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        crate::types::CipherKind::Card(data) => {
            json["cardholder_name"] = serde_json::json!(data.cardholder_name);
            json["brand"] = serde_json::json!(data.brand);
            json["number"] = serde_json::json!(data.number);
            json["exp_month"] = serde_json::json!(data.exp_month);
            json["exp_year"] = serde_json::json!(data.exp_year);
            json["code"] = serde_json::json!(data.code);
        }
        crate::types::CipherKind::Identity(data) => {
            json["title"] = serde_json::json!(data.title);
            json["first_name"] = serde_json::json!(data.first_name);
            json["middle_name"] = serde_json::json!(data.middle_name);
            json["last_name"] = serde_json::json!(data.last_name);
            json["username"] = serde_json::json!(data.username);
            json["company"] = serde_json::json!(data.company);
            json["email"] = serde_json::json!(data.email);
            json["phone"] = serde_json::json!(data.phone);
            json["address1"] = serde_json::json!(data.address1);
            json["address2"] = serde_json::json!(data.address2);
            json["address3"] = serde_json::json!(data.address3);
            json["city"] = serde_json::json!(data.city);
            json["state"] = serde_json::json!(data.state);
            json["postal_code"] = serde_json::json!(data.postal_code);
            json["country"] = serde_json::json!(data.country);
            json["ssn"] = serde_json::json!(data.ssn);
            json["passport_number"] = serde_json::json!(data.passport_number);
            json["license_number"] = serde_json::json!(data.license_number);
        }
        crate::types::CipherKind::SshKey(data) => {
            json["public_key"] = serde_json::json!(data.public_key);
            json["private_key"] = serde_json::json!(data.private_key);
            json["fingerprint"] = serde_json::json!(data.key_fingerprint);
        }
        crate::types::CipherKind::SigningKey(data) => {
            json["public_key"] = serde_json::json!(data.public_key);
            json["private_key"] = serde_json::json!(data.private_key);
            json["passphrase"] = serde_json::json!(data.passphrase);
            json["certificates"] = serde_json::json!(data.certificates);
            json["key_format"] =
                serde_json::to_value(data.key_format).unwrap_or(serde_json::Value::Null);
            json["expires_at"] = serde_json::json!(data.expires_at);
            json["issuer"] = serde_json::json!(data.issuer);
            json["subject"] = serde_json::json!(data.subject);
            json["fingerprint"] = serde_json::json!(data.fingerprint);
        }
        crate::types::CipherKind::BankAccount(data) => {
            json["bank_name"] = serde_json::json!(data.bank_name);
            json["name_on_account"] = serde_json::json!(data.name_on_account);
            json["account_type"] = serde_json::json!(data.account_type);
            json["account_number"] = serde_json::json!(data.account_number);
            json["routing_number"] = serde_json::json!(data.routing_number);
            json["branch_number"] = serde_json::json!(data.branch_number);
            json["pin"] = serde_json::json!(data.pin);
            json["swift_code"] = serde_json::json!(data.swift_code);
            json["iban"] = serde_json::json!(data.iban);
            json["bank_contact_phone"] = serde_json::json!(data.bank_contact_phone);
        }
        crate::types::CipherKind::DriversLicense(data) => {
            json["first_name"] = serde_json::json!(data.first_name);
            json["middle_name"] = serde_json::json!(data.middle_name);
            json["last_name"] = serde_json::json!(data.last_name);
            json["date_of_birth"] = serde_json::json!(data.date_of_birth);
            json["license_number"] = serde_json::json!(data.license_number);
            json["issuing_country"] = serde_json::json!(data.issuing_country);
            json["issuing_state"] = serde_json::json!(data.issuing_state);
            json["issue_date"] = serde_json::json!(data.issue_date);
            json["expiration_date"] = serde_json::json!(data.expiration_date);
            json["issuing_authority"] = serde_json::json!(data.issuing_authority);
            json["license_class"] = serde_json::json!(data.license_class);
        }
        crate::types::CipherKind::Passport(data) => {
            json["surname"] = serde_json::json!(data.surname);
            json["given_name"] = serde_json::json!(data.given_name);
            json["date_of_birth"] = serde_json::json!(data.date_of_birth);
            json["sex"] = serde_json::json!(data.sex);
            json["birth_place"] = serde_json::json!(data.birth_place);
            json["nationality"] = serde_json::json!(data.nationality);
            json["issuing_country"] = serde_json::json!(data.issuing_country);
            json["passport_number"] = serde_json::json!(data.passport_number);
            json["passport_type"] = serde_json::json!(data.passport_type);
            json["national_identification_number"] =
                serde_json::json!(data.national_identification_number);
            json["issuing_authority"] = serde_json::json!(data.issuing_authority);
            json["issue_date"] = serde_json::json!(data.issue_date);
            json["expiration_date"] = serde_json::json!(data.expiration_date);
        }
        crate::types::CipherKind::SecureNote => {}
    }
    json
}
