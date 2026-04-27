import { SdkError } from "./sdk-error.js";

/** @ignore */
export class DomainResolutionError extends SdkError {
  public code: string = "domain_resolution_error";
  constructor(message?: string, public cause?: Error) {
    super(message ?? "Failed to resolve the domain from the request.");
    this.name = "DomainResolutionError";
  }
}

/** @ignore */
export class DomainValidationError extends SdkError {
  public code: string = "domain_validation_error";
  constructor(message?: string) {
    super(message ?? "The domain failed validation.");
    this.name = "DomainValidationError";
  }
}

/** @ignore */
export class IssuerValidationError extends SdkError {
  public code: string = "issuer_validation_error";
  constructor(public expectedIssuer: string, public actualIssuer: string) {
    super(`Issuer Mismatch: expected "${expectedIssuer}" but received "${actualIssuer}"`);
    this.name = "IssuerValidationError";
  }
}

/** @ignore */
export class SessionDomainMismatchError extends SdkError {
  public code: string = "session_domain_mismatch";
  constructor(message?: string) {
    super(message ?? "The session domain does not match the current request domain.");
    this.name = "SessionDomainMismatchError";
  }
}
