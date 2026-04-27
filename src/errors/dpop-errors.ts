import { SdkError } from "./sdk-error.js";

/** @ignore */
export enum DPoPErrorCode {
  DPOP_JKT_CALCULATION_FAILED = "dpop_jkt_calculation_failed",
  DPOP_KEY_EXPORT_FAILED = "dpop_key_export_failed",
  DPOP_CONFIGURATION_ERROR = "dpop_configuration_error"
}

/** @ignore */
export class DPoPError extends SdkError {
  public code: DPoPErrorCode;
  public cause?: Error;
  constructor(code: DPoPErrorCode, message: string, cause?: Error) {
    super(message);
    this.name = "DPoPError";
    this.code = code;
    this.cause = cause;
  }
}
