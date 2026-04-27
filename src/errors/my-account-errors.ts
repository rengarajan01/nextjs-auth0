import { SdkError } from "./sdk-error.js";

/** @ignore */
export class MyAccountApiError extends SdkError {
  public name: string = "MyAccountApiError";
  public code: string = "my_account_api_error";
  public type: string;
  public title: string;
  public detail: string;
  public status: number;
  public validationErrors?: Array<{
    detail: string;
    field?: string;
    pointer?: string;
    source?: string;
  }>;

  constructor({ type, title, detail, status, validationErrors }: {
    type: string;
    title: string;
    detail: string;
    status: number;
    validationErrors?: Array<{ detail: string; field?: string; pointer?: string; source?: string }>;
  }) {
    super(`${title}: ${detail}`);
    this.type = type;
    this.title = title;
    this.detail = detail;
    this.status = status;
    this.validationErrors = validationErrors;
  }
}

/** @ignore */
export enum ConnectAccountErrorCodes {
  MISSING_SESSION = "missing_session",
  FAILED_TO_INITIATE = "failed_to_initiate",
  FAILED_TO_COMPLETE = "failed_to_complete"
}

/** @ignore */
export class ConnectAccountError extends SdkError {
  public code: string;
  public cause?: MyAccountApiError;
  constructor({ code, message, cause }: { code: string; message: string; cause?: MyAccountApiError }) {
    super(message);
    this.name = "ConnectAccountError";
    this.code = code;
    this.cause = cause;
  }
}
