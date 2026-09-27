package xyz.actitud.baluard.data

import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileCatalogInput
import xyz.actitud.baluard.MobileSyncStatus
import xyz.actitud.baluard.MobileCreateResult
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.detail.str
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import xyz.actitud.baluard.MobileRecoveryPhrase
import xyz.actitud.baluard.openVault as uniffiOpenVault
import xyz.actitud.baluard.createVaultWithRecovery as uniffiCreateVaultWithRecovery
import xyz.actitud.baluard.MobileCloneJob
import xyz.actitud.baluard.MobileDeviceFlow
import xyz.actitud.baluard.MobileProvider
import xyz.actitud.baluard.MobileProviderConfig
import xyz.actitud.baluard.MobileRepo
import xyz.actitud.baluard.cloneVaultStart as uniffiCloneVaultStart
import xyz.actitud.baluard.connectPat as uniffiConnectPat
import xyz.actitud.baluard.deriveKekForVault as uniffiDeriveKekForVault
import xyz.actitud.baluard.enrollDeviceWithPhrase as uniffiEnrollDeviceWithPhrase
import xyz.actitud.baluard.listVaultRepos as uniffiListVaultRepos
import xyz.actitud.baluard.startDeviceFlow as uniffiStartDeviceFlow

/**
 * Thin wrapper over the UniFFI-generated Kotlin bindings.
 *
 * Exposes the vault lifecycle (Phase 2) + cipher CRUD (Phase 3-4) + generator
 * (Phase 4 prereq). The generated binding functions are top-level Kotlin fns
 * produced by uniffi-bindgen from the Rust `#[uniffi::export]` decls; they land
 * in package `xyz.actitud.baluard` (set in uniffi.toml). Aliased on import to
 * avoid clashing with the repository method names.
 *
 * All vault/cipher ops are `suspend` (UniFFI async -> Kotlin suspend); the
 * Argon2id KDF and git ops run on the parked shared tokio Runtime off the UI
 * thread (plan §3.3).
 */
/** Minimal folder projection for the list filter (from `vault.list_folders` JSON). */
data class MobileFolderInfo(
    val id: String,
    val name: String,
    /** Parent folder id for hierarchy indentation; null = root. */
    val parentId: String? = null,
)

/** Shared-collection row for the home hub (from the role-aware
 * `collections_list` JSON: members see only rows they can open). */
data class MobileCollectionInfo(
    val id: String,
    val name: String,
    /** "read" | "write" | "manage" for members; "admin" on managing devices. */
    val access: String = "read",
)

/** The caller's own pending access ask (from `requests_mine` JSON). */
data class MobileAskInfo(
    val id: String,
    val collectionId: String,
    val access: String = "read",
)

/** Catalog row for the ask-dialog picker (admin-curated names). */
data class MobileCatalogEntry(
    val id: String,
    val name: String,
)

/** Member row for the People screen (from `members_list` JSON). */
data class MobileMemberInfo(
    val id: String,
    val name: String,
    val role: String = "editor",
    val trust: String = "",
    val reset: Boolean = false,
    val removed: Boolean = false,
    val isSelf: Boolean = false,
)

/** Queued join introduction (from `requests_list` JSON). */
data class MobileJoinRequest(
    val reqId: String,
    val displayName: String,
    val secretOk: Boolean = true,
)

/** Member access ask for the admin inbox (from `collections.requests_list`). */
data class MobileAccessAsk(
    val requestId: String,
    val requesterMemberId: String,
    val requesterName: String,
    val collectionId: String,
    val collectionName: String,
    val access: String = "read",
    val note: String = "",
)

/** Existing grant row inside an admin collection row. */
data class MobileGrantInfo(
    val memberId: String,
    val access: String = "read",
    val expiresAt: Long? = null,
)

/** Admin collection row with its grants inline (one parse per refresh). */
data class MobileCollectionFull(
    val info: MobileCollectionInfo,
    val grants: List<MobileGrantInfo> = emptyList(),
)

/** §6.5 Space policy knobs as read from the daemon. */
data class MobileSpaceSettings(
    val inviteAuthority: String,
    val allowViewerExport: Boolean,
    val guestEnabled: Boolean,
    val trashPolicy: String,
)

/** Team-shape readiness + state (S3-7b). */
data class MobileSpaceStatus(
    val prepared: Boolean,
    val wrapped: Int,
    val missingWrapPubkey: Int,
    val flipped: Boolean,
)

/** Prepare report: wraps minted, members still to sign in. */
data class MobileSpacePrepare(
    val smkFresh: Boolean,
    val wrapped: Int,
    val missing: Int,
)

/** Flip report. */
data class MobileSpaceFlip(
    val alreadyFlipped: Boolean,
    val filesReencrypted: Int,
    val keywrapsRemoved: Int,
)

/** A needs-attention notice: name-carrying (reset_pending) or
 * count-carrying (stale_invite, malformed_requests, grant_*). */
data class MobileNotice(
    val kind: String,
    val name: String?,
    val count: Long?,
)

/** One local share-event row: {seq, at, kind, detail}. */
data class MobileActivityRow(
    val seq: Long,
    val at: Long,
    val kind: String,
    val detail: String,
)

class VaultRepository {
    suspend fun generatePassword(config: xyz.actitud.baluard.PasswordConfig): Result<String> =
        runCatching { xyz.actitud.baluard.generatePassword(config) }

    suspend fun generatePassphrase(config: xyz.actitud.baluard.PassphraseConfig): Result<String> =
        runCatching { xyz.actitud.baluard.generatePassphrase(config) }

    suspend fun openVault(path: String): MobileVault = uniffiOpenVault(path)

    /**
     * Argon2id KEK over [password] for the vault at [path] (B5 biometric
     * enroll). Runs the FULL KDF — main-app enroll flow only, never the
     * quick-unlock path (plan §3.7 OOM guard).
     */
    suspend fun deriveKek(path: String, password: String): ByteArray =
        uniffiDeriveKekForVault(path, password)

    /**
     * Create a vault AND surface its 24-word recovery phrase (plan §3.5). The
     * phrase is HPKE-wrapped to meta/recovery.json by the ceremony and shown
     * exactly once here; [MobileCreateResult.vault] is already unlocked.
     */
    suspend fun createVaultWithRecovery(
        path: String,
        password: String,
        deviceName: String,
    ): MobileCreateResult = uniffiCreateVaultWithRecovery(path, password, deviceName)

    suspend fun listCiphers(vault: MobileVault): List<MobileCipherMeta> = vault.listCiphers()
    suspend fun getCipher(vault: MobileVault, id: String, decrypt: Boolean): String =
        vault.getCipher(id, decrypt)
    suspend fun addCipher(vault: MobileVault, payload: String): String = vault.addCipher(payload)
    suspend fun updateCipher(vault: MobileVault, payload: String): Unit = vault.updateCipher(payload)
    suspend fun deleteCipher(vault: MobileVault, id: String): Unit = vault.deleteCipher(id)
    suspend fun totpCode(vault: MobileVault, id: String): String = vault.totpCode(id)

    /** Generate an SSH keypair (ed25519 | ecdsa256). JSON {public_key,
     * fingerprint, private_key}. Formatted strings only. */
    suspend fun sshGenerateKey(vault: MobileVault, keyType: String): String =
        vault.sshGenerateKey(keyType)

    /** Fetch a favicon for a URI or domain. Returns JSON {data, mime}, or ""
     * when the fetch_favicons setting is off or the fetch failed. */
    suspend fun fetchFavicon(vault: MobileVault, domainOrUri: String): String =
        vault.fetchFavicon(domainOrUri)

    /** All known tags (tag index) for autocomplete. */
    suspend fun listTags(vault: MobileVault): List<String> {
        val raw = runCatching { vault.listTags() }.getOrNull() ?: return emptyList()
        val arr = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(raw) as? kotlinx.serialization.json.JsonArray
        }.getOrNull() ?: return emptyList()
        return arr.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
    }

    /** Raw decrypted settings JSON (theme, lang, fetch_favicons, ...). */
    suspend fun getSettings(vault: MobileVault): String? =
        runCatching { vault.getSettings() }.getOrNull()

    /** Partial settings merge (daemon semantics: only provided keys change).
     * Returns false on FFI failure. */
    suspend fun saveSettings(vault: MobileVault, payload: String): Boolean =
        runCatching { vault.setSettings(payload) }.isSuccess

    /** Live auto-sync status (pending changes / state) for the
     * remove-from-device guard: removal requires idle + zero pending. */
    suspend fun syncStatus(vault: MobileVault): MobileSyncStatus = vault.syncStatus()

    /** Entries with a TOTP seed (hub Authenticator card). */
    suspend fun listTotp(vault: MobileVault): List<MobileCipherMeta> = vault.listTotpCiphers()

    /** Archived entries (Archive card). */
    suspend fun listArchived(vault: MobileVault): List<MobileCipherMeta> = vault.listArchivedCiphers()

    /** Trashed entries (Trash card). */
    suspend fun listTrash(vault: MobileVault): List<MobileCipherMeta> = vault.listTrashCiphers()

    /** Archive a cipher: hide from main list, search, and suggestions. */
    suspend fun archiveCipher(vault: MobileVault, id: String) = vault.archiveCipher(id)

    /** Unarchive a cipher: return it to the main list. */
    suspend fun unarchiveCipher(vault: MobileVault, id: String) = vault.unarchiveCipher(id)

    /** Restore a trashed cipher back to the active vault. */
    suspend fun restoreCipher(vault: MobileVault, id: String) = vault.restoreCipher(id)

    /** Folders as [{id, name, parent_id}] for the list filter. Empty when the vault has none. */
    suspend fun listFolders(vault: MobileVault): List<MobileFolderInfo> {
        val raw = vault.listFolders()
        val arr = kotlinx.serialization.json.Json.parseToJsonElement(raw)
            as? kotlinx.serialization.json.JsonArray ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val id = (o["id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val name = (o["name"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (id != null && name != null) MobileFolderInfo(
                id = id,
                name = name,
                parentId = o.str("parent_id"),
            ) else null
        }
    }

    // ── Sharing surfaces (§4.8-6): thin wrappers over the uniffi
    // methods, which delegate to the same runtime wrappers the desktop
    // daemon routes through. JSON in / JSON out — the payload contracts
    // live in baluard-runtime state.rs, never re-implemented here.

    /** Role-aware shared-collections list (raw JSON: managing devices
     * get grants arrays, members get openable rows only). */
    suspend fun collectionsList(vault: MobileVault): String =
        vault.collectionsList()

    /** Ask for access: {collection_id, access, note?} → {request_id}. */
    suspend fun collectionRequestAccess(vault: MobileVault, payload: String): String =
        vault.collectionRequestAccess(payload)

    /** The caller's own pending asks (raw JSON). */
    suspend fun collectionRequestsMine(vault: MobileVault): String =
        vault.collectionRequestsMine()
    suspend fun collectionRequestsList(vault: MobileVault): String =
        vault.collectionRequestsList()

    /** Withdraw a pending ask: {request_id}. */
    suspend fun collectionRequestsWithdraw(vault: MobileVault, payload: String): String =
        vault.collectionRequestsWithdraw(payload)

    /** Optional plaintext catalog (raw JSON). */
    suspend fun collectionCatalogList(vault: MobileVault): String =
        vault.collectionCatalogList()

    /** Member-side join: {code, password, device_name} → {intro_code}. */
    suspend fun joinIntroduce(vault: MobileVault, code: String, password: String, deviceName: String): String =
        vault.joinIntroduce(code, password, deviceName)

    /** Join status poll: {introduced, approved}. */
    suspend fun joinPoll(vault: MobileVault): String = vault.joinPoll()

    /** Parsed shared-collection rows for the home hub: members see only
     * rows they can open; names arrive decrypted. */
    suspend fun listCollections(vault: MobileVault): List<MobileCollectionInfo> {
        val raw = runCatching { collectionsList(vault) }.getOrNull() ?: return emptyList()
        val obj = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        }.getOrNull() ?: return emptyList()
        val arr = obj["collections"] as? kotlinx.serialization.json.JsonArray
            ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val id = (o["id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val name = (o["name"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (id != null && name != null) MobileCollectionInfo(
                id = id,
                name = name,
                access = (o["access"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "read",
            ) else null
        }
    }

    /** Parsed own pending asks for the ask dialog: [{id, collection_id,
    * access, created_at}]. */
    suspend fun listMyAsks(vault: MobileVault): List<MobileAskInfo> {
        val raw = runCatching { collectionRequestsMine(vault) }.getOrNull() ?: return emptyList()
        val obj = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        }.getOrNull() ?: return emptyList()
        val arr = obj["requests"] as? kotlinx.serialization.json.JsonArray
            ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val id = (o["id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val cid = (o["collection_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (id != null && cid != null) MobileAskInfo(
                id = id,
                collectionId = cid,
                access = (o["access"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "read",
            ) else null
        }
    }

    /** Parsed catalog rows for the ask dialog picker. */
    suspend fun listCatalog(vault: MobileVault): List<MobileCatalogEntry> {
        val raw = runCatching { collectionCatalogList(vault) }.getOrNull() ?: return emptyList()
        val obj = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        }.getOrNull() ?: return emptyList()
        val arr = obj["catalog"] as? kotlinx.serialization.json.JsonArray
            ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val id = (o["collection_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val name = (o["name"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (id != null && name != null) MobileCatalogEntry(id = id, name = name) else null
        }
    }

    // ── §4.8-7 admin surfaces: same wrappers the desktop daemon routes.

    suspend fun membersList(vault: MobileVault): String = vault.membersList()
    suspend fun memberInvite(vault: MobileVault, payload: String): String =
        vault.memberInvite(payload)
    suspend fun joinRequestsList(vault: MobileVault): String = vault.joinRequestsList()
    suspend fun joinRequestsApprove(vault: MobileVault, reqId: String): String =
        vault.joinRequestsApprove("{\"req_id\":\"$reqId\"}")
    suspend fun joinRequestsDeny(vault: MobileVault, reqId: String): String =
        vault.joinRequestsDeny("{\"req_id\":\"$reqId\"}")
    /** Grant collection access: {id, member_id, access, expires_at?}.
     * expires_at is an absolute epoch second (client clock conversion,
     * desktop F4 parity); absent = never. */
    suspend fun collectionGrant(vault: MobileVault, payload: String): String =
        vault.collectionGrant(payload)

    /** Revoke a member's collection access: {id, member_id}. */
    suspend fun collectionRevoke(vault: MobileVault, payload: String): String =
        vault.collectionRevoke(payload)

    // ── §4.8-9 collection CRUD (admin): typed args at the FFI, the
    // bridge builds the payload JSON, the app never hand-escapes ids.

    /** The precise admin marker: this device holds the Root Key. True
     * even for zero-collection vaults where counting admin rows fails. */
    suspend fun isAdminDevice(vault: MobileVault): Boolean =
        runCatching { vault.isAdminDevice() }.getOrDefault(false)

    /** §6.5 Space policy: {space_invite_authority, allow_viewer_export,
     * guest_enabled, trash_policy, restore_policy}. Null on failure —
     * the caller toasts. */
    suspend fun spaceSettingsGet(vault: MobileVault): MobileSpaceSettings? =
        runCatching {
            val o = Json.parseToJsonElement(vault.spaceSettingsGet()).jsonObject
            MobileSpaceSettings(
                inviteAuthority =
                    (o["space_invite_authority"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "admins",
                allowViewerExport = (o["allow_viewer_export"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true",
                guestEnabled = (o["guest_enabled"] as? kotlinx.serialization.json.JsonPrimitive)?.content != "false",
                trashPolicy =
                    (o["trash_policy"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "write_scope_can_trash",
            )
        }.getOrNull()

    /** Set Space policy knobs (partial). One call per changed knob; the
     * typed args reach the bridge, which builds the JSON payload.
     * restore_policy has no setter — v1 is single-valued (admins only). */
    suspend fun spaceSettingsSet(
        vault: MobileVault,
        inviteAuthority: String? = null,
        allowViewerExport: Boolean? = null,
        guestEnabled: Boolean? = null,
        trashPolicy: String? = null,
    ) {
        vault.spaceSettingsSet(inviteAuthority, allowViewerExport, guestEnabled, trashPolicy)
    }

    /** Team-shape readiness + state (S3-7b). Null on failure — the
     * caller toasts rather than rendering a half-card. */
    suspend fun spaceStatus(vault: MobileVault): MobileSpaceStatus? =
        runCatching {
            val o = Json.parseToJsonElement(vault.spaceStatus()).jsonObject
            MobileSpaceStatus(
                prepared = (o["prepared"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true",
                wrapped = ((o["wrapped"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "0").toIntOrNull() ?: 0,
                // SpaceStatus.missing_wrap_pubkey is a COUNT (usize);
                // only the prepare report carries the id array.
                missingWrapPubkey =
                    ((o["missing_wrap_pubkey"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "0").toIntOrNull() ?: 0,
                flipped = (o["flipped"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true",
            )
        }.getOrNull()

    /** Mint/refresh member key wraps ahead of the flip. Null on
     * failure; the report lists members that still must sign in. */
    suspend fun spacePrepare(vault: MobileVault): MobileSpacePrepare? =
        runCatching {
            val o = Json.parseToJsonElement(vault.spacePrepare()).jsonObject
            MobileSpacePrepare(
                smkFresh = (o["smk_fresh"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true",
                wrapped = ((o["wrapped"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "0").toIntOrNull() ?: 0,
                missing = (o["missing_wrap_pubkey"] as? kotlinx.serialization.json.JsonArray)?.size ?: 0,
            )
        }.getOrNull()

    /** One-way flip to team shape. Throws on refusal — the caller
     * shows the daemon's plain-language error. */
    suspend fun spaceFlip(vault: MobileVault): MobileSpaceFlip {
        val o = Json.parseToJsonElement(vault.spaceFlip()).jsonObject
        return MobileSpaceFlip(
            alreadyFlipped = (o["already_flipped"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true",
            filesReencrypted =
                ((o["files_reencrypted"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "0").toIntOrNull() ?: 0,
            keywrapsRemoved =
                ((o["keywraps_removed"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "0").toIntOrNull() ?: 0,
        )
    }

    // ── S1b: notices + activity (this device's local data; the phone
    // passes refresh_transport=false so no forge network runs).

    /** Needs-attention notices. Null on failure — the caller toasts. */
    suspend fun noticesList(vault: MobileVault): List<MobileNotice> =
        runCatching {
            val o = Json.parseToJsonElement(vault.noticesList(false)).jsonObject
            val arr = o["notices"]?.jsonArray ?: emptyList()
            arr.mapNotNull { el ->
                val n = el.jsonObject
                MobileNotice(
                    kind = n.str("kind") ?: return@mapNotNull null,
                    name = n.str("name"),
                    count = n.str("count")?.toLongOrNull(),
                )
            }
        }.getOrDefault(emptyList())

    /** This device's share events. The core emits chronological
     * (oldest-first); reversed here so the UI contract is newest-first.
     * Empty on failure. */
    suspend fun activityEvents(vault: MobileVault, limit: ULong = 100u): List<MobileActivityRow> =
        runCatching {
            Json.parseToJsonElement(vault.activityEvents(limit)).jsonArray.mapNotNull { el ->
                val r = el.jsonObject
                MobileActivityRow(
                    seq = (r["seq"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull()
                        ?: return@mapNotNull null,
                    at = (r["at"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() ?: 0,
                    kind = r.str("kind").orEmpty(),
                    detail = r.str("detail").orEmpty(),
                )
            }
        }.getOrDefault(emptyList()).reversed()

    /** This device's refusal log lines. Empty on failure. */
    suspend fun activityRefusals(vault: MobileVault, limit: ULong = 50u): List<String> =
        runCatching {
            Json.parseToJsonElement(vault.activityRefusals(limit)).jsonArray.mapNotNull { el ->
                (el as? kotlinx.serialization.json.JsonPrimitive)?.content
            }
        }.getOrDefault(emptyList())

    /** Mint a collection → {id}. */
    suspend fun collectionCreate(vault: MobileVault, name: String): String =
        vault.collectionCreate(name)

    /** Rename a collection → {ok: true}. */
    suspend fun collectionRename(vault: MobileVault, id: String, name: String): String =
        vault.collectionRename(id, name)

    /** Delete a collection (grants die with it; entries preserved). */
    suspend fun collectionDelete(vault: MobileVault, id: String): String =
        vault.collectionDelete(id)

    /** Publish the request catalog: the given rows become askable by
     * name. An empty list clears the catalog (opt-out). */
    suspend fun collectionCatalogSet(vault: MobileVault, entries: List<MobileCatalogInput>): String =
        vault.collectionCatalogSet(entries)
    // §4.8-8 offboarding: the bridge builds the JSON payloads from typed
    // args, so the app never hand-escapes member ids.
    suspend fun memberReset(vault: MobileVault, memberId: String): String =
        vault.memberReset(memberId)
    suspend fun memberTransfer(vault: MobileVault, memberId: String): String =
        vault.memberTransfer(memberId)
    suspend fun memberRemove(
        vault: MobileVault,
        memberIds: List<String>,
        offlineOverride: Boolean,
    ): String = vault.memberRemove(memberIds, offlineOverride)

    /** Approve an access ask; access is the admin's final say (read or
     * write preset). Payload contract per the runtime wrapper. */
    suspend fun collectionRequestApprove(
        vault: MobileVault,
        requestId: String,
        requesterMemberId: String,
        access: String,
    ): String = vault.collectionRequestsApprove(
        "{\"request_id\":\"$requestId\",\"requester_member_id\":\"$requesterMemberId\",\"access\":\"$access\"}",
    )

    /** Deny an access ask; the payload contract requires the requester id. */
    suspend fun collectionRequestDeny(
        vault: MobileVault,
        requestId: String,
        requesterMemberId: String,
    ): String = vault.collectionRequestsDeny(
        "{\"request_id\":\"$requestId\",\"requester_member_id\":\"$requesterMemberId\"}",
    )

    /** Parsed member rows for the People screen; tombstoned rows kept so
     * the UI can grey them out. */
    suspend fun listMembers(vault: MobileVault): List<MobileMemberInfo> {
        val raw = runCatching { membersList(vault) }.getOrNull() ?: return emptyList()
        val obj = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        }.getOrNull() ?: return emptyList()
        val arr = obj["members"] as? kotlinx.serialization.json.JsonArray
            ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val id = (o["id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val name = (o["display_name"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (id != null && name != null) MobileMemberInfo(
                id = id,
                name = name,
                role = (o["role"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "editor",
                trust = (o["trust"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                reset = (o["reset"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true",
                removed = (o["removed"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true",
                isSelf = (o["is_self"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true",
            ) else null
        }
    }

    /** One-time reset code handed back to the member (members.reset). */
    data class MobileResetResult(val successorId: String, val resetCode: String)

    /** Offboarding report (members.remove): what was struck and what
     *  could not be — the UI surfaces unstruck seats prominently. */
    data class MobileRemoveReport(
        val removedCount: Int,
        val newEpoch: Long,
        val seatsStruck: List<String>,
        val unstruckSeats: List<String>,
    )

    /** Parse the members.reset response; null on malformed input. */
    fun parseResetResult(raw: String): MobileResetResult? = runCatching {
        val o = kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        MobileResetResult(
            successorId = (o["successor_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
            resetCode = (o["reset_code"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
        )
    }.getOrNull()

    /** Parse the members.remove report; null on malformed input. */
    fun parseRemoveReport(raw: String): MobileRemoveReport? = runCatching {
        val o = kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        fun strList(key: String): List<String> =
            (o[key] as? kotlinx.serialization.json.JsonArray)
                ?.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                .orEmpty()
        MobileRemoveReport(
            removedCount = (o["removed"] as? kotlinx.serialization.json.JsonArray)?.size
                ?: (o["removed"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull()
                ?: 0,
            newEpoch = (o["new_epoch"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() ?: 0L,
            seatsStruck = strList("seats_struck"),
            unstruckSeats = strList("unstruck_seats"),
        )
    }.getOrNull()

    /** Parsed queued join introductions for the People screen. */
    suspend fun listJoinRequests(vault: MobileVault): List<MobileJoinRequest> {
        val raw = runCatching { joinRequestsList(vault) }.getOrNull() ?: return emptyList()
        val obj = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        }.getOrNull() ?: return emptyList()
        val arr = obj["requests"] as? kotlinx.serialization.json.JsonArray
            ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val reqId = (o["req_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val name = (o["display_name"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (reqId != null && name != null) MobileJoinRequest(
                reqId = reqId,
                displayName = name,
                secretOk = (o["secret_ok"] as? kotlinx.serialization.json.JsonPrimitive)?.content != "false",
            ) else null
        }
    }

    /** Parsed access asks for the admin inbox; malformed count dropped —
     * the desktop inbox surfaces it, mobile keeps the rows. */
    suspend fun listAccessAsks(vault: MobileVault): List<MobileAccessAsk> {
        val raw = runCatching { collectionRequestsList(vault) }.getOrNull() ?: return emptyList()
        val obj = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        }.getOrNull() ?: return emptyList()
        val arr = obj["requests"] as? kotlinx.serialization.json.JsonArray
            ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val rid = (o["request_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val mid = (o["requester_member_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            val cid = (o["collection_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (rid != null && mid != null && cid != null) MobileAccessAsk(
                requestId = rid,
                requesterMemberId = mid,
                requesterName = (o["requester_name"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                collectionId = cid,
                collectionName = (o["collection_name"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                access = (o["access"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "read",
                note = (o["note"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
            ) else null
        }
    }

    /** Admin rows with grants inline — ONE bridge call serves both the
     * collection list and every grants editor (review F2: the grants
     * array rides the same admin rows; re-fetching per collection was
     * an N+1 bridge round-trip pattern). */
    suspend fun listCollectionsFull(vault: MobileVault): List<MobileCollectionFull> {
        val raw = runCatching { collectionsList(vault) }.getOrNull() ?: return emptyList()
        val obj = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
        }.getOrNull() ?: return emptyList()
        val arr = obj["collections"] as? kotlinx.serialization.json.JsonArray
            ?: return emptyList()
        return arr.mapNotNull { el ->
            val o = el as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
            val id = (o["id"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: return@mapNotNull null
            val name = (o["name"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: return@mapNotNull null
            val grants = (o["grants"] as? kotlinx.serialization.json.JsonArray)?.mapNotNull { g ->
                val go = g as? kotlinx.serialization.json.JsonObject ?: return@mapNotNull null
                val mid = (go["member_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content
                    ?: return@mapNotNull null
                MobileGrantInfo(
                    memberId = mid,
                    access = (go["access"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "read",
                    expiresAt = (go["expires_at"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull(),
                )
            }.orEmpty()
            MobileCollectionFull(
                info = MobileCollectionInfo(
                    id = id,
                    name = name,
                    access = (o["access"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "read",
                ),
                grants = grants,
            )
        }
    }
// ── Slice B: provider onboarding (plan §4) ──

    /** Start an RFC 8628 device-flow session; poll via [MobileDeviceFlow.poll]. */
    suspend fun startDeviceFlow(
        provider: MobileProvider,
        config: MobileProviderConfig = MobileProviderConfig(null, null),
    ): MobileDeviceFlow = uniffiStartDeviceFlow(provider, config)

    /** Connect with a personal access token (Codeberg default; works for all). */
    suspend fun connectPat(
        provider: MobileProvider,
        token: String,
        config: MobileProviderConfig = MobileProviderConfig(null, null),
    ) = uniffiConnectPat(provider, token, config)

    /** Repos that look like Baluard vaults on the connected account. */
    suspend fun listVaultRepos(provider: MobileProvider): List<MobileRepo> =
        uniffiListVaultRepos(provider)

    /** Clone a vault repo to [localPath]. Cancel via the returned job. */
    suspend fun cloneVaultStart(
        provider: MobileProvider,
        cloneUrl: String,
        localPath: String,
    ): MobileCloneJob = uniffiCloneVaultStart(provider, cloneUrl, localPath)

    /**
     * Enroll this device into an existing vault clone with the 24-word
     * recovery phrase (plan §2.4: clone -> enroll -> unlock). Returns the
     * vault already unlocked.
     */
    suspend fun enrollDeviceWithPhrase(
        vaultPath: String,
        masterPassword: String,
        recoveryPhrase: String,
        deviceName: String,
    ): MobileVault = uniffiEnrollDeviceWithPhrase(vaultPath, masterPassword, recoveryPhrase, deviceName)

    /** Persist the vault auto-lock timeout token. */
    suspend fun setVaultTimeout(vault: MobileVault, token: String) {
        vault.setSettings("""{"vault_timeout": "$token"}""")
    }

    companion object {
        const val DEFAULT_VAULT_TIMEOUT = "15m"

        /** Auto-lock presets (mirrors baluard-core VaultTimeout wire tokens). */
        val vaultTimeoutPresets = listOf(
            VaultTimeoutPreset("immediately", 0L, "settings.autoLock.immediately"),
            VaultTimeoutPreset("1m", 1L, "settings.autoLock.1m"),
            VaultTimeoutPreset("5m", 5L, "settings.autoLock.5m"),
            VaultTimeoutPreset("10m", 10L, "settings.autoLock.10m"),
            VaultTimeoutPreset("15m", 15L, "settings.autoLock.15m"),
            VaultTimeoutPreset("30m", 30L, "settings.autoLock.30m"),
            VaultTimeoutPreset("1h", 60L, "settings.autoLock.1h"),
            VaultTimeoutPreset("4h", 240L, "settings.autoLock.4h"),
            VaultTimeoutPreset("on_app_exit", null, "settings.autoLock.onAppExit"),
        )
    }
}

/** Vault auto-lock preset (wire token + minutes + i18n label key). */
data class VaultTimeoutPreset(
    val token: String,
    val minutes: Long?,
    val labelKey: String,
)

/** Minutes for a token; null = never auto-lock (on_app_exit). */
fun vaultTimeoutMinutes(token: String): Long? =
    VaultRepository.vaultTimeoutPresets.firstOrNull { it.token == token }?.minutes

/** Helper: read + normalize the vault auto-lock timeout token. */
suspend fun vaultTimeoutToken(vault: MobileVault): String {
    val json = runCatching { vault.getSettings() }.getOrNull()
        ?: return VaultRepository.DEFAULT_VAULT_TIMEOUT
    val raw = runCatching {
        kotlinx.serialization.json.Json.parseToJsonElement(json)
            .jsonObject["vault_timeout"]?.jsonPrimitive?.content
    }.getOrNull()
    return VaultRepository.vaultTimeoutPresets
        .firstOrNull { it.token == raw?.trim()?.lowercase() }?.token
        ?: VaultRepository.DEFAULT_VAULT_TIMEOUT
}


/** i18n label key for a timeout token. */
fun vaultTimeoutLabel(token: String): String =
    VaultRepository.vaultTimeoutPresets.firstOrNull { it.token == token }?.labelKey
        ?: "settings.autoLock.15m"
