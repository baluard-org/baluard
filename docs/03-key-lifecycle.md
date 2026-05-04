# IDtty: Key Lifecycle & Cryptographic Design

> Comprehensive key lifecycle for the Rust Core Engine and Space storage engine.
> Covers: key types, escrow, creation ceremony, and Zero-Knowledge RBAC sharing mechanics.

---

## Summary Table

| Key Type | Primitive | Stored Where | Purpose | Lifetime / Rotation |
|----------|-----------|--------------|---------|---------------------|
| **Master Password** | Plaintext user input | Never stored | Derived into Master KEK | Ephemeral in RAM; discarded after KDF |
| **Master KEK** | Argon2id, 256-bit | Process memory (`zeroize`-protected) | Decrypts escrowed Device Private Key | Purged on vault locking or daemon exit |
| **Device Private Key** | X25519, 256-bit | Decrypted: `zeroize` buffer. Escrowed: `metadata/identity.enc` | Decrypts Space Group Key from access list | Permanent; wrapped with Master Password in repo |
| **Space Group Key** | AES-256-GCM | Decrypted: `zeroize` buffer. Wrapped: `metadata/access_list.json` | Encrypts entries and lookup index (`index.enc`) | Rotated on member offboarding or manual rekey |
| **Commit Signing Key** | Ed25519 | Private: Escrowed in repo. Public: Git host / Access List | Cryptographically signs Git commits | Permanent; bound to Digital Identity |

---

## 1. Key Wrapping & Escrow Mechanics

### 1.1 Private Key Escrow (`metadata/identity.enc`)
To support bootstrap on new devices without manual peer-to-peer verification:
1. When a vault (Space) is initialized, a unique Device Asymmetric Keypair (X25519/Ed25519) is generated.
2. The private key is symmetrically encrypted using the **Master KEK** (derived via Argon2id).
3. The encrypted private key is committed to the Git repository as `metadata/identity.enc`.
4. On a new device, the user clones the repo via GitHub/GitLab OAuth, types their Master Password, decrypts the escrowed private key, and imports it to the local OS Keychain / Enclave.

### 1.2 Access List Wrapping (`metadata/access_list.json`)
Sharing a Space relies on envelope encryption:
1. Every Space possesses a symmetric **Space Group Key** (AES-256-GCM).
2. The `metadata/access_list.json` contains a map of member public keys to their corresponding wrapped copies of the Group Key:
   ```json
   {
     "members": [
       {
         "email": "member@example.com",
         "device_id": "uuid-here",
         "public_key": "X25519_PUBLIC_HEX",
         "wrapped_group_key": "HPKE_CIPHERTEXT_HEX"
       }
     ]
   }
   ```
3. A member opens a Space by decapsulating their `wrapped_group_key` with their local escrowed Device Private Key.

---

## 2. Cryptographic Ceremonies

### 2.1 Space Creation Ceremony
1. **Key Generation**: idtty-core generates the X25519 and Ed25519 keys for the first device.
2. **Space Group Key**: idtty-core generates a random 256-bit AES key for the Space.
3. **Escrow wrapping**: Master Password is run through Argon2id to yield KEK; KEK encrypts the private key into `metadata/identity.enc`.
4. **Access wrapping**: Space Group Key is wrapped with the first device's public key and written to `metadata/access_list.json`.
5. **Lookup index**: An empty lookup table is created, AES-GCM encrypted with the Space Group Key, and written to `index.enc`.
6. **Git Initialization**: git2-rs initializes the repository, commits all files (including an initial dummy entry), and pushes to the Git provider using the OAuth PAT stored in the OS Keyring.

### 2.2 Member Invitation & Acceptance
1. **Invite**: The Space Admin enters the invitee's email. idtty-core queries the Git provider (GitHub/GitLab) for the invitee's public key.
2. **Wrapping**: idtty-core encrypts the Space Group Key with the invitee's public key, appends the wrapped payload to `metadata/access_list.json`, and pushes.
3. **Accept**: The invitee logs in via OAuth, clones the Space, inputs their Master Password to fetch their device identity, decapsulates the Space Group Key from `access_list.json`, and unlocks the local database.

### 2.3 Offboarding Rekey Flow
When a member is removed from a Space:
1. **Group Key Rotation**: idtty-core generates a brand new 256-bit Space Group Key.
2. **Re-encryption**: idtty-core decrypts all entries under `entries/` using the old Group Key, pads them to their respective uniform buckets (1KB, 8KB, 64KB, 1MB), and re-encrypts them using the new Group Key.
3. **Access List Update**: idtty-core removes the revoked member's public key and entry from `metadata/access_list.json`. It re-encrypts the new Group Key for all remaining members using their public keys.
4. **Index Rebuild**: Re-encrypts the lookup index `index.enc` with the new Group Key.
5. **Git Push**: idtty-core commits the re-encrypted entries and the modified metadata files, then force-pushes the state to the Git provider. The revoked user's local instance is completely locked out of updates, and their local clone contains outdated, unreadable entries.
