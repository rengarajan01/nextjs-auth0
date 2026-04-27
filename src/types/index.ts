import { AuthorizationParameters } from "./authorize.js";
import { ConnectionTokenSet } from "./token-vault.js";

/** @ignore */
export interface TokenSet {
  accessToken: string;
  idToken?: string;
  scope?: string;
  requestedScope?: string;
  refreshToken?: string;
  expiresAt: number; // the time at which the access token expires in seconds since epoch
  audience?: string;
  token_type?: string; // the type of the access token (e.g., "Bearer", "DPoP")
}

/** @ignore */
export interface AccessTokenSet {
  accessToken: string;
  scope?: string;
  requestedScope?: string;
  audience: string;
  expiresAt: number; // the time at which the access token expires in seconds since epoch
  token_type?: string; // the type of the access token (e.g., "Bearer", "DPoP")
}

/**
 * The full session object stored by the SDK. Available in `beforeSessionSaved` and
 * `onCallback` hooks, and returned by `getSession()`.
 *
 * @group Server
 * @title Session Data
 * @order 40
 */
export interface SessionData {
  user: User;
  tokenSet: TokenSet;
  accessTokens?: AccessTokenSet[];
  internal: {
    // the session ID from the authorization server
    sid: string;
    // the time at which the session was created in seconds since epoch
    createdAt: number;
    // MCD metadata: domain and issuer used to authenticate this session
    mcd?: import("./mcd.js").MCDMetadata;
  };
  connectionTokenSets?: ConnectionTokenSet[];
  [key: string]: unknown;
}

/**
 * Interface for a custom session data store. Implement this and pass it to
 * `AbstractSessionStore` to use a custom backend (Redis, database, etc.) for sessions.
 *
 * **TTL contract:** every successful write method (`set`, `update`) must reset the session
 * TTL/expiry so that active sessions are not silently expired between requests.
 *
 * @group Server
 * @title Session Data Store
 * @order 41
 */
export interface SessionDataStore {
  /**
   * Gets the session from the store given a session ID.
   */
  get(id: string): Promise<SessionData | null>;

  /**
   * Upsert a session in the store given a session ID and `SessionData`.
   */
  set(id: string, session: SessionData): Promise<void>;

  /**
   * Optional: update the session by its ID only if it already exists.
   * Return `true` if updated, `false` if not found.
   */
  update?(id: string, session: SessionData): Promise<boolean>;

  /**
   * Destroys the session with the given session ID.
   */
  delete(id: string): Promise<void>;

  /**
   * Deletes the session with the given logout token which may contain a session ID or a user ID, or both.
   *
   * **MCD resolver mode:** When using multiple custom domains with a domain resolver,
   * implementations MUST filter on the `iss` field in addition to `sub`/`sid` to
   * ensure sessions are only deleted for the matching issuer.
   */
  deleteByLogoutToken?(logoutToken: LogoutToken): Promise<void>;
}

/**
 * The logout token shape passed to `SessionDataStore.deleteByLogoutToken()`.
 *
 * @group Server
 * @title Logout Token
 * @order 42
 */
export type LogoutToken = { sub?: string; sid?: string; iss?: string };

/**
 * The authenticated user object available on `session.user`.
 * Standard OIDC claims plus any custom claims added via Auth0 Actions.
 *
 * @group Server
 * @title User
 * @order 43
 */
export interface User {
  sub: string;
  name?: string;
  nickname?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  /**
   * The organization ID that the user belongs to.
   * This field is populated when the user logs in through an organization.
   */
  org_id?: string;

  [key: string]: any;
}

export type {
  Auth0ClientOptions,
  PagesRouterRequest,
  PagesRouterResponse
} from "../server/client.js";

export type {
  BeforeSessionSavedHook,
  OnCallbackHook,
  RoutesOptions,
  OnCallbackContext,
  Routes
} from "../server/auth-client.js";

/** @ignore */
export type { TransactionCookieOptions } from "../server/transaction-store.js";

export type {
  SessionConfiguration,
  SessionCookieOptions,
  SessionStoreOptions
} from "../server/session/abstract-session-store.js";

/** @ignore */
export type {
  CookieOptions,
  ReadonlyRequestCookies
} from "../server/cookies.js";

/** @ignore */
export type {
  TransactionStoreOptions,
  TransactionState
} from "../server/transaction-store.js";

/**
 * Controls which logout endpoint the SDK uses.
 *
 * - `"auto"` (default): uses OIDC RP-Initiated Logout if the discovery document advertises it, otherwise falls back to the Auth0 `/v2/logout` endpoint.
 * - `"oidc"`: always use OIDC RP-Initiated Logout.
 * - `"v2"`: always use the Auth0 `/v2/logout` endpoint.
 *
 * @group Server
 * @title Logout Strategy
 * @order 44
 */
export type LogoutStrategy = "auto" | "oidc" | "v2";

/**
 * Options for initiating a Client-Initiated Backchannel Authentication (CIBA) flow
 * via `getTokenByBackchannelAuth()`.
 *
 * @group Server
 * @title Backchannel Authentication Options
 * @order 45
 */
export interface BackchannelAuthenticationOptions {
  /**
   * Human-readable message displayed at both the consumption device and the authentication device.
   */
  bindingMessage: string;
  /**
   * The login hint identifying which user to authenticate.
   */
  loginHint: {
    /**
     * The `sub` claim of the user that is trying to login using Client-Initiated Backchannel Authentication.
     */
    sub: string;
  };
  /**
   * Custom expiry time for the CIBA flow in seconds. Defaults to 300 seconds (5 minutes).
   */
  requestedExpiry?: number;
  /**
   * Optional authorization details for Rich Authorization Requests (RAR).
   * @see https://auth0.com/docs/get-started/apis/configure-rich-authorization-requests
   */
  authorizationDetails?: AuthorizationDetails[];
  /**
   * Authorization parameters to be sent with the authorization request.
   */
  authorizationParams?: AuthorizationParameters;
}

/**
 * Response from a successful Client-Initiated Backchannel Authentication (CIBA) flow.
 *
 * @group Server
 * @title Backchannel Authentication Response
 * @order 46
 */
export interface BackchannelAuthenticationResponse {
  tokenSet: TokenSet;
  idTokenClaims?: { [key: string]: any };
  authorizationDetails?: AuthorizationDetails[];
}

/**
 * Rich Authorization Request detail object.
 * @see https://auth0.com/docs/get-started/apis/configure-rich-authorization-requests
 *
 * @group Server
 * @title Authorization Details
 * @order 47
 */
export interface AuthorizationDetails {
  readonly type: string;
  readonly [parameter: string]: unknown;
}

/**
 * Options for `getAccessToken()`.
 *
 * @group Server
 * @title Get Access Token Options
 * @order 48
 */
export type GetAccessTokenOptions = {
  refresh?: boolean | null;
  scope?: string | null;
  /**
   * Please note: If you are passing audience, ensure that the used audiences and scopes are
   * part of the Application's Refresh Token Policies in Auth0 when configuring Multi-Resource Refresh Tokens (MRRT).
   * {@link https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token|See Auth0 Documentation on Multi-resource Refresh Tokens}
   */
  audience?: string | null;
};

/** @ignore */
export type ProxyOptions = {
  proxyPath: string;
  targetBaseUrl: string;
  audience: string;
  scope: string | null;
};

export {
  AuthorizationParameters,
  StartInteractiveLoginOptions
} from "./authorize.js";
export {
  AccessTokenForConnectionOptions,
  ConnectionTokenSet,
  CustomTokenExchangeOptions,
  CustomTokenExchangeResponse,
  GRANT_TYPE_CUSTOM_TOKEN_EXCHANGE,
  SUBJECT_TOKEN_TYPES
} from "./token-vault.js";
export { ConnectAccountOptions, RESPONSE_TYPES } from "./connected-accounts.js";
export {
  MfaClient,
  Authenticator,
  ChallengeResponse,
  EnrollmentResponse,
  EnrollOptions,
  EnrollOtpOptions,
  EnrollOobOptions,
  MfaVerifyResponse,
  VerifyMfaOptions,
  VerifyMfaOptionsBase,
  VerifyMfaWithOtpOptions,
  VerifyMfaWithOobOptions,
  VerifyMfaWithRecoveryCodeOptions,
  MfaContext,
  GRANT_TYPE_MFA_OTP,
  GRANT_TYPE_MFA_OOB,
  GRANT_TYPE_MFA_RECOVERY_CODE
} from "./mfa.js";

export type {
  DomainResolver,
  DiscoveryCacheOptions,
  MCDMetadata
} from "./mcd.js";

export type { DpopKeyPair, DpopOptions, RetryConfig } from "./dpop.js";
