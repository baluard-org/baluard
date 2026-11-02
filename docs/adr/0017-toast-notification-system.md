# ADR 0017. Toast Notification System

> Status: Accepted (completed 2026-06-09)

## Context

User feedback needs a shared presentation mechanism across the application rather than component-specific inline status text. Inline messages require per-component state, shift the layout when they appear, and are lost when the component unmounts, which happens on lock and vault switch (ADR 0012).

## Decision

The frontend uses standalone signal-based notifications, defined at module level and not inside a provider so that they survive lock and unlock and can be called from any context or library module. `toastSignal.js` provides `toastSuccess(message)` and `toastError(message)`, which `ToastContainer.jsx` consumes. All user feedback is presented as toasts; the UI does not use inline messages such as "Profile saved" or "Copied!". Message text comes from translation keys (ADR 0019).

The implementation has since extended the original two helpers. A general `toast(type, message, opts)` accepts the types `success`, `error`, `warning`, and `info`, with options for the auto-dismiss duration and a manual dismiss button. Defaults are 4 seconds for a plain toast, 5 seconds for `toastWarning`, and 6 seconds with a manual dismiss button for `toastError`, so that errors cannot vanish before they are read.

## Consequences

Success, warning, and error feedback share one notification container and one signal interface, and feedback behavior is uniform across features. Because toasts are transient, any message that must persist until acted upon (for example a conflict or an unlock requirement) needs a banner or dialog instead, as the conflict banner and unlock banners do.

## References

- `toastSignal.js`
- `ToastContainer.jsx`
