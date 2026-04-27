import { SdkError } from "./sdk-error.js";

/** @ignore */
export class OAuth2Error extends SdkError {
  public code: string;
  constructor({ code, message }: { code: string; message?: string }) {
    super(message ?? "An error occurred while interacting with the authorization server.");
    this.name = "OAuth2Error";
    this.code = code;
  }
}

/** @ignore */
export class DiscoveryError extends SdkError {
  public code: string = "discovery_error";
  constructor(message?: string) {
    super(message ?? "Discovery failed for the OpenID Connect configuration.");
    this.name = "DiscoveryError";
  }
}

/** @ignore */
export class MissingStateError extends SdkError {
  public code: string = "missing_state";
  constructor(message?: string) {
    super(message ?? "The state parameter is missing.");
    this.name = "MissingStateError";
  }
}

/** @ignore */
export class InvalidStateError extends SdkError {
  public code: string = "invalid_state";
  constructor(message?: string) {
    super(message ?? "The state parameter is invalid.");
    this.name = "InvalidStateError";
  }
}

/** @ignore */
export class InvalidConfigurationError extends SdkError {
  public code: string = "invalid_configuration";
  constructor(message?: string) {
    super(message ?? "The configuration is invalid.");
    this.name = "InvalidConfigurationError";
  }
}

/** @ignore */
export class AuthorizationError extends SdkError {
  public code: string = "authorization_error";
  public cause: OAuth2Error;
  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(message ?? "An error occurred during the authorization flow.");
    this.cause = cause;
    this.name = "AuthorizationError";
  }
}

/** @ignore */
export class AuthorizationCodeGrantRequestError extends SdkError {
  public code: string = "authorization_code_grant_request_error";
  constructor(message?: string) {
    super(message ?? "An error occurred while preparing or performing the authorization code grant request.");
    this.name = "AuthorizationCodeGrantRequestError";
  }
}

/** @ignore */
export class AuthorizationCodeGrantError extends SdkError {
  public code: string = "authorization_code_grant_error";
  public cause: OAuth2Error;
  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(message ?? "An error occurred while trying to exchange the authorization code.");
    this.cause = cause;
    this.name = "AuthorizationCodeGrantError";
  }
}

/** @ignore */
export class BackchannelLogoutError extends SdkError {
  public code: string = "backchannel_logout_error";
  constructor(message?: string) {
    super(message ?? "An error occurred while completing the backchannel logout request.");
    this.name = "BackchannelLogoutError";
  }
}

/** @ignore */
export class BackchannelAuthenticationNotSupportedError extends SdkError {
  public code: string = "backchannel_authentication_not_supported_error";
  constructor() {
    super("The authorization server does not support backchannel authentication. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-client-initiated-backchannel-authentication");
    this.name = "BackchannelAuthenticationNotSupportedError";
  }
}

/** @ignore */
export class BackchannelAuthenticationError extends SdkError {
  public code: string = "backchannel_authentication_error";
  public cause?: OAuth2Error;
  constructor({ cause }: { cause?: OAuth2Error }) {
    super("There was an error when trying to use Client-Initiated Backchannel Authentication.");
    this.cause = cause;
    this.name = "BackchannelAuthenticationError";
  }
}

/** @ignore */
export enum AccessTokenErrorCode {
  MISSING_SESSION = "missing_session",
  MISSING_REFRESH_TOKEN = "missing_refresh_token",
  FAILED_TO_REFRESH_TOKEN = "failed_to_refresh_token"
}

/** @ignore */
export class AccessTokenError extends SdkError {
  public code: string;
  public cause?: OAuth2Error;
  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);
    this.name = "AccessTokenError";
    this.code = code;
    this.cause = cause;
  }
}

/** @ignore */
export enum AccessTokenForConnectionErrorCode {
  MISSING_SESSION = "missing_session",
  MISSING_REFRESH_TOKEN = "missing_refresh_token",
  FAILED_TO_EXCHANGE = "failed_to_exchange_refresh_token"
}

/** @ignore */
export class AccessTokenForConnectionError extends SdkError {
  public code: string;
  public cause?: OAuth2Error;
  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);
    this.name = "AccessTokenForConnectionError";
    this.code = code;
    this.cause = cause;
  }
}

/** @ignore */
export enum CustomTokenExchangeErrorCode {
  MISSING_SUBJECT_TOKEN = "missing_subject_token",
  INVALID_SUBJECT_TOKEN_TYPE = "invalid_subject_token_type",
  MISSING_ACTOR_TOKEN_TYPE = "missing_actor_token_type",
  EXCHANGE_FAILED = "exchange_failed"
}

/** @ignore */
export class CustomTokenExchangeError extends SdkError {
  public code: string;
  public cause?: OAuth2Error;
  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);
    this.name = "CustomTokenExchangeError";
    this.code = code;
    this.cause = cause;
  }
}
