package xyz.actitud.baluard.autofill

import android.widget.inline.InlinePresentationSpec

/**
 * Inline suggestion specs captured from the last FillRequest (plan 2b/S2).
 * The post-biometric rebuild in [AutofillActivity] has no FillRequest of its
 * own; the specs from the original request are still valid for its
 * EXTRA_AUTHENTICATION_RESULT, so they ride along in this process-singleton.
 * Styles only, never credentials; process death clears it harmlessly.
 */
object AutofillInlineCache {
    // Single-writer assumption: the last fill request wins. A second request
    // overwriting specs while an earlier one awaits biometric only affects
    // chip styling, never credentials (peer-review finding #7, accepted).
    var specs: List<InlinePresentationSpec> = emptyList()
    var maxCount: Int = 0

    fun update(specs: List<InlinePresentationSpec>, maxCount: Int) {
        this.specs = specs
        this.maxCount = maxCount
    }
}
