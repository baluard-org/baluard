import { createSignal, Show, For } from "solid-js";

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
  const [expanded, setExpanded] = createSignal(true);
  const hasChildren = () => (props.node.children || []).length > 0;

  return (
    <div>
      <div
        class={`flex items-center gap-1 px-3.5 py-1.5 rounded-xl text-xs font-bold cursor-pointer ${props.selectedFolder?.() === props.node.id ? "bg-[var(--color-sidebar)] text-[var(--color-text)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"}`}
        style={{ "padding-left": `${12 + props.depth * 16}px` }}
        onClick={() => props.setSelectedFolder?.(props.node.id)}
      >
        {hasChildren() ? (
          <button
            onClick={e => { e.stopPropagation(); setExpanded(!expanded()); }}
            class="p-0.5 rounded hover:bg-black/10 cursor-pointer shrink-0"
          >
            <svg class={`w-3 h-3 transition-transform ${expanded() ? "rotate-90" : ""}`} fill="currentColor" viewBox="0 0 20 20"><path d="M6 4l8 6-8 6V4z"/></svg>
          </button>
        ) : <span class="w-4 shrink-0" />}
        <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
        <span class="truncate">{props.node.name}</span>
      </div>
      <Show when={hasChildren() && expanded()}>
        <For each={props.node.children || []}>
          {(child) => <FolderNode node={child} depth={props.depth + 1} selectedFolder={props.selectedFolder} setSelectedFolder={props.setSelectedFolder} />}
        </For>
      </Show>
    </div>
  );
}
