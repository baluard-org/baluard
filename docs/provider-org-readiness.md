# Provider Org-Readiness Checklist

**Date:** 2026-09-27
**Scope:** The plan-sharing.md S3 gate: "Free-tier seat/quota and ToS-for-non-code-data table verified per provider before S3." This file records the verified facts and the gate conditions an org-shape Space must satisfy before it can ship on each provider.
**Sources:** Provider primary documents fetched 2026-09-27 (linked inline). Facts drift; re-verify before an org-Space release. The 2026-06-15 app-registration matrix lives in `git-provider-apps-and-tokens.md` and is not repeated here.

## 1. The verified matrix

| Dimension | GitHub | GitLab (SaaS) | Codeberg (Forgejo) |
|---|---|---|---|
| **Free-tier seats** | Orgs: unlimited collaborators on Free. | **Top-level groups created now: max 5 members** while private. Older groups (pre-2022) are grandfathered. Public visibility is uncapped. Premium lifts the cap. | No seat charge (donation-funded). Org accounts free. |
| **Storage quota** | No hard repo quota in the docs; guidance keeps repos under ~1 GB (archives near 5 GB), 100 MB per-file push block. Baluard's padded buckets (KB-MB) fit comfortably. | Repo/storage limits vary by tier and are not a practical blocker at Baluard's sizes. | **Git storage 750 MiB per user/org; private repos + personal-use repos share a 100 MiB "non-promoted" total.** Exception form exists but is manual review. |
| **Non-code data in ToS** | Allowed. The ToS defines "Content" to include data; private-repo contents are confidential (ToS section E, effective 2026-04-27). No code-only restriction. | Allowed for private projects; no non-code-storage prohibition in the terms. | **Constrained.** ToU section 1 reserves the service for FLOSS projects; section 2(1)2 allows private repos for "things required for FLOSS projects, like storing secrets" and "really small and personal stuff ... but explicitly not as a personal cloud or media storage." |
| **Org third-party app approval** | Org owners can enable OAuth App access restrictions and approve/deny apps per org; GitHub Apps install per-org with request/approval flows; fine-grained PATs are org-policy-gated (docs: "Approving OAuth apps for your organization"). | Group-level: no per-app approval gate comparable to GitHub's; scope is the token's own scope (`api`, `read_api`, `write_repository`). Instance admins govern self-hosted. | Forgejo OAuth apps have no scopes (full account access, documented 2026-06-15); no org-level app-approval concept. Org owners manage members/teams directly. |
| **Repo ownership for org Spaces** | Any member's account or an org-owned repo. Org ownership keeps `baluard-*` repos under employer-visible admin control; fine-grained PATs/Apps can scope to the org only. | Group-owned repos (the org shape). Personal namespaces hit the 5-member cap; group membership is the seat. | Org-owned repos, subject to the FLOSS-mission clause above. |

## 2. Findings that change decisions

1. **GitLab free tier seats are the hard wall for team Spaces.** A group created today on GitLab.com Free admits 5 members. The org-Space product must either (a) require Premium for more than 5-member GitLab Spaces, (b) point large teams at self-managed instances (the `instance_url` override already ships), or (c) warn at connect time. The connect-time scope-honesty surface should carry this.
2. **Codeberg cannot host a real team Space.** A private `baluard-space-*` repo sits in the 100 MiB non-promoted bucket; vault history grows with every rotation (structural, per the sharing plan's history-bloat note). 100 MiB is weeks of use for a small team. Codeberg stays viable for personal vaults (small, and "journal/config/notes" is explicitly allowed) and for FLOSS-project secret storage within 750 MiB. An org-Space rollout should default Codeberg off with this explanation, not fail mysteriously at quota.
3. **GitHub is the only provider with a real app-approval gate, and that is good for org Spaces.** The corporate security-review story (the reason the plan requires fine-grained PATs or a GitHub App for org use) maps directly onto a procurement conversation: the org owner approves one installation scoped to `baluard-*` repos and nothing else. The classic-OAuth `repo` scope reads every repo on the account, which corporate review will reject.
4. **GitHub ToS does not prohibit password vaults.** Verified against the current ToS text: private-repo content is confidential, "Content" includes data, and no clause limits repos to source code. The folk claim that password managers violate GitHub ToS is wrong for private repos; the Acceptable Use Policies still apply (no illegal content, etc.).

## 3. The org-Space readiness gate (the checklist itself)

An org-shape Space may only be created on a provider connection that answers yes to all of:

- **Repo ownership** — the Space's remote will live under an account or group the org controls (not one employee's personal namespace that leaves with them).
- **App approval path exists** — the provider can grant Baluard access to exactly the Space's repos without exposing the rest of the org (GitHub: App installation or fine-grained PAT scoped to `baluard-*`; GitLab: group-scoped token; Codeberg: not available, see finding 2).
- **Scope honesty shown** — the connect surface states exactly what the token can read, including the classic-scope blast radius, before the user approves.
- **Seats fit** — the expected member count fits the provider's free tier, or the plan for paying is stated (GitLab more than 5 members).
- **ToS fit** — the Space's purpose fits the provider's terms (Codeberg: FLOSS-project secrets only; no personal-cloud usage).

Until org-shape Spaces exist (S4 planning), this checklist is the pass condition recorded per provider: **GitHub ready** (with the App/fine-grained requirement), **GitLab ready with the 5-seat caveat**, **Codeberg personal-only**.

## 4. Sources

- GitHub ToS (effective 2026-04-27): https://docs.github.com/en/site-policy/github-terms/github-terms-of-service (section A.6 "Content", section E Private Repositories).
- GitHub org OAuth approval: https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/approving-oauth-apps-for-your-organization and the restrictions/limits pages.
- GitLab free user limit: https://docs.gitlab.com/user/free_user_limit/ (five users, newly created top-level namespaces, private visibility).
- Codeberg Terms of Use: https://codeberg.org/Codeberg/org/raw/branch/main/TermsOfUse.md (sections 1(2), 2(1)2, 2(1)5-7).
- Codeberg storage quotas (rolled out from 2025-05-16): https://blog.codeberg.org/new-storage-limits-on-codeberg-what-you-need-to-know.html (750 MiB git, 1.5 GiB LFS/releases, 100 MiB non-promoted).
