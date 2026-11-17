package app.baluard.mobile.autofill

import android.app.assist.AssistStructure
import android.view.autofill.AutofillId
import app.baluard.mobile.platform.A11yUri
import app.baluard.mobile.platform.FieldView
import app.baluard.mobile.platform.FlatField
import app.baluard.mobile.platform.FormParser

/**
 * AssistStructure adapter for [FormParser]: walks a structure's view tree,
 * flattens it into rows (including the Material hint-container redirect),
 * and hands the decision logic to the pure parser. Used by the fill path
 * ([BaluardAutofillService]) and the fallback-pick return path
 * ([AutofillActivity]): the picker re-parses the structure the system
 * attached to the auth launch so the returned dataset binds the CURRENT
 * field ids, not the request-time pinned ones.
 */
object AutofillFormParser {
    /** Parsed login form: the fields to fill plus the match target. */
    data class Form(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?,
        val target: String,
        val ignoredIds: List<AutofillId> = emptyList(),
    ) {
        val fields: AutofillResponseBuilder.TargetFields
            get() = AutofillResponseBuilder.TargetFields(usernameId, passwordId)
    }

    fun parse(structure: AssistStructure): Form? {
        val rows = mutableListOf<FlatField>()
        for (i in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(i)
            walkNode(window.rootViewNode) { node ->
                // Material TextInputLayout redirection (Bitwarden parity):
                // hint-carrying containers cannot accept values - redirect
                // to the first text-autofillable descendant.
                val container = isHintContainer(node)
                val effective = if (container) firstTextDescendant(node) else node
                val target = effective ?: node
                var field = adapt(target)
                if (container && node.hint != null) field = field.copy(hint = node.hint)
                rows += FlatField(field, isEditableInput(target))
            }
        }
        val packageName = structure.activityComponent?.packageName
        val parsed = FormParser.parse(rows, packageName, A11yUri.isBrowserPackage(packageName))
            ?: return null
        return Form(
            usernameId = parsed.usernameId as? AutofillId,
            passwordId = parsed.passwordId as? AutofillId,
            target = parsed.target,
            ignoredIds = parsed.ignoredIds.filterIsInstance<AutofillId>(),
        )
    }

    internal fun isEditableInput(node: AssistStructure.ViewNode): Boolean =
        node.autofillType != android.view.View.AUTOFILL_TYPE_NONE &&
            node.className?.toString()?.contains("EditText") == true

    /**
     * Hint-carrying container that cannot accept values itself (Material
     * TextInputLayout pattern): redirects classification to its inner text
     * field (Bitwarden findFirstAutofillableChild parity).
     */
    private fun isHintContainer(node: AssistStructure.ViewNode): Boolean =
        node.autofillType == android.view.View.AUTOFILL_TYPE_NONE &&
            node.childCount > 0 &&
            (!node.hint.isNullOrBlank() || !node.autofillHints.isNullOrEmpty())

    private fun firstTextDescendant(
        node: AssistStructure.ViewNode,
        depth: Int = 0,
    ): AssistStructure.ViewNode? {
        if (depth > MAX_CONTAINER_DEPTH) return null
        for (i in 0 until node.childCount) {
            val child = node.getChildAt(i) ?: continue
            if (child.autofillType == android.view.View.AUTOFILL_TYPE_TEXT) return child
            firstTextDescendant(child, depth + 1)?.let { return it }
        }
        return null
    }

    private const val MAX_CONTAINER_DEPTH = 10

    internal fun adapt(node: AssistStructure.ViewNode): FieldView {
        val attrs = node.htmlInfo?.attributes.orEmpty()
        fun attr(name: String): String? = attrs
            .firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

        return FieldView(
            autofillId = node.autofillId,
            hints = node.autofillHints?.toList().orEmpty(),
            inputType = node.inputType,
            idEntry = node.idEntry,
            hint = node.hint,
            text = node.text?.toString(),
            htmlAutocomplete = attr("autocomplete"),
            webDomain = node.webDomain,
            htmlTag = node.htmlInfo?.tag,
            htmlType = attr("type"),
            htmlName = attr("name"),
            htmlId = attr("id"),
            htmlLabel = attr("label"),
        )
    }

    internal fun walkNode(node: AssistStructure.ViewNode, visit: (AssistStructure.ViewNode) -> Unit) {
        visit(node)
        for (i in 0 until node.childCount) walkNode(node.getChildAt(i), visit)
    }
}
