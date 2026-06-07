import { IconFolder, IconPlus, IconX, IconPencil } from "./Icon.jsx";
import { createSignal, Show, For } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { buildFolderCreatePayload } from "../lib/payload.js";
import { useVault } from "../context/VaultContext.jsx";
import { useI18n } from "../i18n/index.jsx";

export function FolderTree(props) {
  // Build tree from flat list
  const tree = () => {
    const folders = props.folders || [];
    const roots = folders.filter(f => !f.parent_id);
    return roots.map(r => buildNode(r, folders));
  };

  function buildNode(folder, allFolders) {
    const children = allFolders.filter(f => f.parent_id === folder.id);
    return { ...folder, children: children.map(c => buildNode(c, allFolders)) };
  }

  return <For each={tree()}>
    {(node) => <FolderNode node={node} depth={0} selectedFolder={props.selectedFolder} setSelectedFolder={props.setSelectedFolder} />}
  </For>;
}

export function FolderNode(props) {
  const vault = useVault();
  const { t } = useI18n();
  const [expanded, setExpanded] = createSignal(true);
  const [hovered, setHovered] = createSignal(false);
  const [renaming, setRenaming] = createSignal(false);
  const [addingChild, setAddingChild] = createSignal(false);
  const [confirmingDelete, setConfirmingDelete] = createSignal(false);

  const hasChildren = () => (props.node.children || []).length > 0;
  const depth = () => props.depth;
  const indent = () => 14 + depth() * 16;

  async function refreshFolders() {
    try { await vault.refreshCiphers(t); } catch {}
  }

  async function handleRename(e) {
    const name = e.target.value.trim();
    if (name && name !== props.node.name) {
      try { await daemon("folder.rename", JSON.stringify({ id: props.node.id, name })); } catch {}
      await refreshFolders();
    }
    setRenaming(false);
  }

  async function handleCreateChild(e) {
    const name = e.target.value.trim();
    if (name) {
      try { await daemon("folder.create", JSON.stringify(buildFolderCreatePayload(name, props.node.id))); } catch {}
      await refreshFolders();
    }
    setAddingChild(false);
  }

  async function handleDelete(e) {
    e.stopPropagation();
    try {
      await daemon("folder.delete", props.node.id);
      await refreshFolders();
      // If deleted folder was selected, deselect
      if (vault.selectedFolder() === props.node.id) vault.setSelectedFolder(null);
    } catch {}
  }

  return (
    <div>
      <div
        class={`group/folder flex items-center gap-1 py-1.5 rounded-xl text-xs font-bold cursor-pointer transition-colors ${
          vault.selectedFolder() === props.node.id
            ? "bg-[var(--color-sidebar)] text-[var(--color-text)]"
            : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"
        }`}
        style={{ "padding-left": `${indent()}px`, "padding-right": "6px" }}
        onClick={() => vault.setSelectedFolder(props.node.id)}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => { setHovered(false); }}
      >
        {hasChildren() ? (
          <button
            onClick={e => { e.stopPropagation(); setExpanded(!expanded()); }}
            class="p-0.5 rounded hover:bg-black/10 cursor-pointer shrink-0"
          >
            <svg class={`w-3 h-3 transition-transform ${expanded() ? "rotate-90" : ""}`} fill="currentColor" viewBox="0 0 20 20"><path d="M6 4l8 6-8 6V4z"/></svg>
          </button>
        ) : (depth() > 0 ? <span class="w-4 shrink-0" /> : null)}
        <IconFolder class="w-3.5 h-3.5 shrink-0" />

        <Show when={renaming()} fallback={
          <span class="truncate flex-1 min-w-0">{props.node.name}</span>
        }>
          <input
            class="flex-1 min-w-0 bg-transparent border-b border-[var(--color-primary)] text-xs text-[var(--color-text)] outline-none pb-px"
            value={props.node.name}
            onKeyDown={async (e) => {
              if (e.key === "Enter") { e.target.blur(); }
              if (e.key === "Escape") { setRenaming(false); }
            }}
            onBlur={(e) => handleRename(e)}
            onClick={e => e.stopPropagation()}
            autofocus
          />
        </Show>

        {/* Hover toolbar */}
        <Show when={hovered() && !renaming()}>
          <div class="ml-auto flex items-center gap-0.5 shrink-0 pl-1">
            <button title="Add subfolder"
              class="p-0.5 rounded hover:bg-[var(--color-sidebar)] text-[var(--color-muted)] hover:text-[var(--color-primary)] cursor-pointer"
              onClick={e => { e.stopPropagation(); setExpanded(true); setAddingChild(true); }}>
              <IconPlus class="w-3 h-3" />
            </button>
            <button title="Rename"
              class="p-0.5 rounded hover:bg-[var(--color-sidebar)] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
              onClick={e => { e.stopPropagation(); setRenaming(true); }}>
              <IconPencil class="w-3 h-3" />
            </button>
            <Show when={confirmingDelete()} fallback={
              <button title="Delete folder"
                class="p-0.5 rounded hover:bg-red-500/10 text-[var(--color-muted)] hover:text-red-400 cursor-pointer"
                onClick={e => { e.stopPropagation(); setConfirmingDelete(true); setTimeout(() => setConfirmingDelete(false), 3000); }}>
                <IconX class="w-3 h-3" />
              </button>
            }>
              <button title="Confirm delete"
                class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-950/40 text-red-400 border border-red-900/30 hover:bg-red-950/60 cursor-pointer whitespace-nowrap"
                onClick={e => { e.stopPropagation(); setConfirmingDelete(false); handleDelete(e); }}>
                Delete?
              </button>
            </Show>
          </div>
        </Show>
      </div>

      {/* Sub-folder ghost row */}
      <Show when={addingChild()}>
        <div
          class="flex items-center gap-1 py-1.5 rounded-xl pr-1.5"
          style={{ "padding-left": `${14 + (depth() + 1) * 16}px` }}
        >
          <span class="w-4 shrink-0" />
          <IconFolder class="w-3.5 h-3.5 shrink-0 text-[var(--color-primary)] opacity-50" />
          <input
            class="flex-1 min-w-0 bg-transparent border-b border-[var(--color-primary)] text-xs text-[var(--color-text)] outline-none placeholder:text-[var(--color-muted)] pb-px"
            placeholder="Subfolder name"
            autofocus
            onKeyDown={async (e) => {
              if (e.key === "Enter") { await handleCreateChild(e); }
              if (e.key === "Escape") { setAddingChild(false); }
            }}
            onBlur={() => setAddingChild(false)}
          />
        </div>
      </Show>

      <Show when={hasChildren() && expanded()}>
        <For each={props.node.children || []}>
          {(child) => <FolderNode node={child} depth={props.depth + 1} selectedFolder={props.selectedFolder} setSelectedFolder={props.setSelectedFolder} />}
        </For>
      </Show>
    </div>
  );
}
