package xyz.actitud.baluard.detail

/**
 * Read-only field schema per cipher type (detail screen). Wire keys are the
 * serde field names on the Rust `CipherKind` data structs (`types.rs`);
 * labels are i18n keys. `sensitive` fields render masked with a reveal
 * toggle; `mono` fields render monospace.
 *
 * Tags match the serde-tagged enum: {type: "login"|"card"|...} (camelCase).
 */
data class FieldSpec(
    val labelKey: String,
    val wireKey: String,
    val sensitive: Boolean = false,
    val mono: Boolean = false,
)

/** i18n key for a cipher type's display name. */
internal fun typeLabelKey(tag: String): String = "detail.type.${normalizeTypeTag(tag)}"

/** Map the FFI's lowercase Debug tag ("sshkey") to the serde wire tag ("sshKey"). */
internal fun normalizeTypeTag(tag: String): String = when (tag.lowercase()) {
    "sshkey" -> "sshKey"
    "securenote" -> "secureNote"
    "bankaccount" -> "bankAccount"
    "driverslicense" -> "driversLicense"
    else -> tag
}

internal fun fieldsFor(tag: String): List<FieldSpec> = when (tag) {
    "login" -> listOf(
        FieldSpec("edit.username", "username"),
        FieldSpec("edit.password", "password", sensitive = true, mono = true),
    )
    "card" -> listOf(
        FieldSpec("detail.f.cardholder", "cardholder_name"),
        FieldSpec("detail.f.brand", "brand"),
        FieldSpec("detail.f.number", "number", sensitive = true, mono = true),
        FieldSpec("detail.f.expMonth", "exp_month"),
        FieldSpec("detail.f.expYear", "exp_year"),
        FieldSpec("detail.f.code", "code", sensitive = true, mono = true),
    )
    "identity" -> listOf(
        FieldSpec("detail.f.title", "title"),
        FieldSpec("detail.f.firstName", "first_name"),
        FieldSpec("detail.f.middleName", "middle_name"),
        FieldSpec("detail.f.lastName", "last_name"),
        FieldSpec("edit.username", "username"),
        FieldSpec("detail.f.company", "company"),
        FieldSpec("detail.f.email", "email"),
        FieldSpec("detail.f.phone", "phone"),
        FieldSpec("detail.f.city", "city"),
        FieldSpec("detail.f.state", "state"),
        FieldSpec("detail.f.postalCode", "postal_code"),
        FieldSpec("detail.f.country", "country"),
        FieldSpec("detail.f.ssn", "ssn", sensitive = true, mono = true),
        FieldSpec("detail.f.passportNumber", "passport_number", sensitive = true, mono = true),
        FieldSpec("detail.f.licenseNumber", "license_number", sensitive = true, mono = true),
    )
    "sshKey" -> listOf(
        FieldSpec("detail.f.publicKey", "public_key", mono = true),
        FieldSpec("detail.f.fingerprint", "key_fingerprint", mono = true),
        FieldSpec("detail.f.privateKey", "private_key", sensitive = true, mono = true),
    )
    "bankAccount" -> listOf(
        FieldSpec("detail.f.bankName", "bank_name"),
        FieldSpec("detail.f.nameOnAccount", "name_on_account"),
        FieldSpec("detail.f.accountType", "account_type"),
        FieldSpec("detail.f.accountNumber", "account_number", sensitive = true, mono = true),
        FieldSpec("detail.f.routingNumber", "routing_number", sensitive = true, mono = true),
        FieldSpec("detail.f.branchNumber", "branch_number", sensitive = true, mono = true),
    )
    "driversLicense" -> listOf(
        FieldSpec("detail.f.firstName", "first_name"),
        FieldSpec("detail.f.middleName", "middle_name"),
        FieldSpec("detail.f.lastName", "last_name"),
        FieldSpec("detail.f.dateOfBirth", "date_of_birth"),
        FieldSpec("detail.f.licenseNumber", "license_number", sensitive = true, mono = true),
        FieldSpec("detail.f.issuingCountry", "issuing_country"),
    )
    "passport" -> listOf(
        FieldSpec("detail.f.surname", "surname"),
        FieldSpec("detail.f.givenName", "given_name"),
        FieldSpec("detail.f.dateOfBirth", "date_of_birth"),
        FieldSpec("detail.f.sex", "sex"),
        FieldSpec("detail.f.birthPlace", "birth_place"),
        FieldSpec("detail.f.nationality", "nationality"),
        FieldSpec("detail.f.issuingCountry", "issuing_country"),
        FieldSpec("detail.f.passportNumber", "passport_number", sensitive = true, mono = true),
        FieldSpec("detail.f.passportType", "passport_type"),
        FieldSpec("detail.f.nationalId", "national_identification_number", sensitive = true, mono = true),
        FieldSpec("detail.f.issuingAuthority", "issuing_authority"),
        FieldSpec("detail.f.issueDate", "issue_date"),
        FieldSpec("detail.f.expirationDate", "expiration_date"),
    )
    else -> emptyList() // secureNote: notes only
}
