import { SdkError } from "./sdk-error.js";

/** @ignore */
export interface MfaApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

/** @ignore */
abstract class MfaError extends SdkError {
  public abstract readonly error: string;
  public abstract readonly error_description: string;

  toJSON(): { error: string; error_description: string } {
    return { error: this.error, error_description: this.error_description };
  }

  get code(): string {
    return this.error;
  }
}

/** @ignore */
export class InvalidRequestError extends SdkError {
  public code = "invalid_request";
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, InvalidRequestError.prototype);
    this.name = "InvalidRequestError";
  }
  toJSON() {
    return { error: this.code, error_description: this.message };
  }
}

/** @ignore */
export class MfaGetAuthenticatorsError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;
  constructor(error: string, error_description: string, cause?: MfaApiErrorResponse) {
    super(error_description);
    this.name = "MfaGetAuthenticatorsError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaGetAuthenticatorsError.prototype);
  }
}

/** @ignore */
export class MfaChallengeError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;
  constructor(error: string, error_description: string, cause?: MfaApiErrorResponse) {
    super(error_description);
    this.name = "MfaChallengeError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaChallengeError.prototype);
  }
}

/** @ignore */
export class MfaVerifyError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;
  constructor(error: string, error_description: string, cause?: MfaApiErrorResponse) {
    super(error_description);
    this.name = "MfaVerifyError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaVerifyError.prototype);
  }
}

/** @ignore */
export class MfaNoAvailableFactorsError extends SdkError {
  public readonly code: string = "mfa_no_available_factors";
  public readonly error: string = "mfa_no_available_factors";
  public readonly error_description: string;
  constructor(error_description: string) {
    super(error_description);
    this.name = "MfaNoAvailableFactorsError";
    this.error_description = error_description;
    Object.setPrototypeOf(this, MfaNoAvailableFactorsError.prototype);
  }
}

/** @ignore */
export class MfaEnrollmentError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;
  constructor(error: string, error_description: string, cause?: MfaApiErrorResponse) {
    super(error_description);
    this.name = "MfaEnrollmentError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaEnrollmentError.prototype);
  }
}

/** @ignore */
export interface MfaRequirements {
  enroll?: Array<{ type: string }>;
  challenge?: Array<{ type: string }>;
}

/** @ignore */
export class MfaRequiredError extends SdkError {
  public readonly code: string = "mfa_required";
  public readonly mfa_token: string;
  public readonly error: string = "mfa_required";
  public readonly error_description: string;
  public readonly mfa_requirements?: MfaRequirements;
  public readonly cause?: Error;

  constructor(error_description: string, mfaToken: string, mfaRequirements?: MfaRequirements, cause?: Error) {
    super(error_description);
    this.name = "MfaRequiredError";
    this.error_description = error_description;
    this.mfa_token = mfaToken;
    this.mfa_requirements = mfaRequirements;
    this.cause = cause;
  }

  toJSON(): { error: string; error_description: string; mfa_token: string; mfa_requirements?: MfaRequirements } {
    return {
      error: this.error,
      error_description: this.error_description,
      mfa_token: this.mfa_token,
      ...(this.mfa_requirements && { mfa_requirements: this.mfa_requirements })
    };
  }
}

/** @ignore */
export class MfaTokenExpiredError extends SdkError {
  public readonly code: string = "mfa_token_expired";
  constructor() {
    super("MFA token has expired. Please restart the MFA flow.");
    this.name = "MfaTokenExpiredError";
  }
}

/** @ignore */
export class MfaTokenInvalidError extends SdkError {
  public readonly code: string = "mfa_token_invalid";
  constructor() {
    super("MFA token is invalid.");
    this.name = "MfaTokenInvalidError";
  }
}
