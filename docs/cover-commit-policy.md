# Cover Commit Scheduling Policy

**Status:** Active
**Last Updated:** 2026-06-09

## Threat Model

A git remote adversary (compromised host, MITM, or rogue admin) can observe:
- Commit timestamps (git stores author/committer timestamps)
- Push timing (when commits arrive at remote)
- Commit frequency patterns (bursts vs silence)
- Tree diffs (which files changed, sizes)

From these, they can infer:
- Active usage hours → timezone, sleep schedule
- Edit frequency → vault importance, routine
- File count changes → additions/deletions
- Silence gaps → travel, device offline

## Defense: Cover Commits + Static Metadata

Cover commits are no-op commits (same tree as HEAD) that are indistinguishable from real vault updates. Combined with:

1. **Static commit message** (`COMMIT_MESSAGE` constant in engine.rs)
2. **Generic git author** (`"Baluard User" <vault@baluard.local>`)
3. **Encrypted metadata** (folders, tags, profile, activity all `.enc`)
4. **Timestamp normalization** on vault lock
5. **Jitter delay** before network operations (`apply_push_jitter`)

The adversary sees a stream of identical-looking commits at varied intervals.

## Scheduling Policy

### Triggered Cover Commits

After every real vault operation that triggers a `commit_all()`, schedule a cover commit at a random delay:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Min delay | 30 minutes | Prevents immediate follow-on correlation |
| Max delay | 4 hours | Ensures cover fires within half-day |
| Distribution | Uniform random | No predictable pattern |

### Periodic Cover Commits

A background timer fires cover commits independently of user activity:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Interval | 2-6 hours (random) | Masks periods of inactivity |
| Jitter | ±30 minutes | Prevents fixed-interval detection |
| Condition | Vault must be unlocked | No-op if locked |

### Push Policy

Cover commits are NOT automatically pushed. They accumulate locally and get pushed:
- On next explicit `sync.push` (user or scheduled)
- When the periodic auto-sync fires (if enabled)

This avoids creating a detectable push pattern that correlates with cover commit creation.

### Interactions

| Event | Action |
|-------|--------|
| Real commit | Schedule cover commit at T+random(30min, 4hr) |
| Cover commit timer fires | Create no-op commit if vault unlocked |
| Push | Push all local commits (real + cover) with jitter |
| Lock | Cancel pending cover commit timers |
| Unlock | Start periodic cover timer |

## Implementation Notes

- `SyncEngine::cover_commit()` already exists (same tree as HEAD, static message)
- Scheduler lives in daemon `VaultState` (tokio::spawn, cancellable via JoinHandle)
- Timer resets on each real commit (prevents clustering)
- Cover commits update the device activity index (indistinguishable from real)
- No cover commits while vault is locked or during rotation

## Residual Risks

1. **First commit reveals vault creation time** — mitigated by timestamp normalization on lock
2. **Push timing** — mitigated by `apply_push_jitter()` (uniform 1-5 minute delay)
3. **Network silence** — periodic cover commits only work if vault is unlocked; locked vault has no cover traffic
4. **File count changes** — padded buckets already normalize file sizes, but adding/removing entries changes file count in `ciphers/`. Future: dummy file padding
