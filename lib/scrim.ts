// The dim behind a dialog. bb's own dialogs dim with a black-at-40% utility, but a plugin's stylesheet has no `--color-black`, so that class draws nothing there;
// a plain translucent black is the same dim in both themes. The only color literal of the page, kept in one place.
export const SCRIM_STYLE = { backgroundColor: "rgb(0 0 0 / 0.4)" } as const;
