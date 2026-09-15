import { useI18n } from "../i18n/index.jsx";
import ConfirmModal from "./ConfirmModal.jsx";

// Archive confirmation. Pure wrapper over the shared ConfirmModal
// (code-health R5); the amber confirm matches the archive accent.
export default function ArchiveConfirmModal(props) {
  const { t } = useI18n();
  return (
    <ConfirmModal
      show={props.show}
      idPrefix="archive-confirm"
      title={t("entry.archiveTitle")}
      body={t("entry.archiveConfirm")}
      confirmLabel={t("entry.archive")}
      confirmClass="bg-amber-950/40 text-amber-400 border border-amber-900/30 hover:bg-amber-950/65"
      onConfirm={() => props.onConfirm?.()}
      closeOnOverlay={false}
      onClose={() => props.setShow(false)}
    />
  );
}
