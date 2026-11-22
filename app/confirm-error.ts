/** The person closed the confirmation dialog: not an error, nothing is shown. Kept apart from the dialog so that the action runner can tell it without importing the page. */
export class ConfirmCancelled extends Error {
  constructor() {
    super("confirmation cancelled");
  }
}
