import { useI18n } from "../i18n/index.jsx";
import ConfirmModal from "./ConfirmModal.jsx";

// Delete confirmation (trash → permanent, elsewhere → move to trash).
// Pure wrapper over the shared ConfirmModal (code-health R5).
export default function DeleteConfirmModal(props) {
  const { t } = useI18n();
  const inTrash = props.selectedCategory === "Trash";
  return (
    <ConfirmModal
      show={props.showDeleteConfirm}
      idPrefix="delete-confirm"
      title={t("entry.deleteTitle")}
      body={inTrash ? t("entry.deletePermanentlyConfirm") : t("entry.moveToTrashConfirm")}
      confirmLabel={inTrash ? t("entry.deletePermanently") : t("entry.delete")}
      confirmVariant="danger"
      onConfirm={() => props.onDelete?.(props.viewCipher?.id)}
      onClose={() => props.setShowDeleteConfirm(false)}
    />
  );
}
