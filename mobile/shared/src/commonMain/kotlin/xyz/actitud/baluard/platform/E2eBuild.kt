package xyz.actitud.baluard.platform

/**
 * True only in an E2E build (-Pbaluard.e2e, docs/e2e-testing.md Phase 2).
 * Gates behaviors that would otherwise need a human in the loop (the
 * quick-unlock enrollment offer after a successful password unlock).
 * Fail-secure: any build that does not opt in reads false.
 */
expect val e2eBuild: Boolean
