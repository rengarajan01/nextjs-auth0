import type { IncomingMessage, ServerResponse } from "http";
import type { ParsedUrlQuery } from "querystring";
import { cookies, headers as getHeaders } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";
import { NextApiHandler, NextApiRequest, NextApiResponse } from "next/types.js";

import {
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode,
  ConnectAccountError,
  ConnectAccountErrorCodes,
  InvalidConfigurationError,
  MfaRequiredError
} from "../errors/index.js";
import { DpopKeyPair, DpopOptions } from "../types/dpop.js";
import {
  AccessTokenForConnectionOptions,
  AuthorizationParameters,
  BackchannelAuthenticationOptions,
  ConnectAccountOptions,
  CustomTokenExchangeOptions,
  CustomTokenExchangeResponse,
  GetAccessTokenOptions,
  LogoutStrategy,
  SessionData,
  SessionDataStore,
  StartInteractiveLoginOptions,
  User
} from "../types/index.js";
import type { DiscoveryCacheOptions, DomainResolver } from "../types/mcd.js";
import {
  DEFAULT_MFA_CONTEXT_TTL_SECONDS,
  DEFAULT_SCOPES
} from "../utils/constants.js";
import { isRequest } from "../utils/request.js";
import { getSessionChangesAfterGetAccessToken } from "../utils/session-changes-helpers.js";
import { AuthClientProvider } from "./auth-client-provider.js";
import {
  AuthClient,
  BeforeSessionSavedHook,
  OnCallbackHook,
  Routes,
  RoutesOptions
} from "./auth-client.js";
import { RequestCookies, ResponseCookies } from "./cookies.js";
import { DiscoveryCache } from "./discovery-cache.js";
import { AccessTokenFactory, CustomFetchImpl, Fetcher } from "./fetcher.js";
import * as withApiAuthRequired from "./helpers/with-api-auth-required.js";
import {
  appRouteHandlerFactory,
  AppRouterPageRoute,
  AppRouterPageRouteOpts,
  PageRoute,
  pageRouteHandlerFactory,
  WithPageAuthRequiredAppRouterOptions,
  WithPageAuthRequiredPageRouterOptions
} from "./helpers/with-page-auth-required.js";
import { ServerMfaClient } from "./mfa/server-mfa-client.js";
import {
  toHeadersFromIncomingMessage,
  toNextRequest,
  toNextResponse,
  toUrlFromPagesRouter
} from "./next-compat.js";
import {
  AbstractSessionStore,
  SessionConfiguration,
  SessionCookieOptions
} from "./session/abstract-session-store.js";
import { StatefulSessionStore } from "./session/stateful-session-store.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import {
  TransactionCookieOptions,
  TransactionStore
} from "./transaction-store.js";

/**
 * Configuration options for `Auth0Client`. All options can also be set via environment variables.
 *
 * @group Server
 * @title Auth0 Client Options
 * @order 160
 */
export interface Auth0ClientOptions {
  // authorization server configuration
  /**
   * The Auth0 domain for the tenant.
   *
   * - `string`: Static domain (e.g., `"example.us.auth0.com"`). Existing behavior preserved.
   * - `DomainResolver`: Async function resolving domain per-request from headers.
   *   Enables Multiple Custom Domains (MCD) for B2C multi-brand, B2B SaaS, or domain migration.
   *
   * Falls back to `AUTH0_DOMAIN` environment variable if not provided.
   *
   * @see {@link DomainResolver} for resolver signature and examples.
   * @see [MCD Examples](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#multiple-custom-domains-mcd)
   */
  domain?: string | DomainResolver;
  /**
   * The Auth0 client ID.
   *
   * If it's not specified, it will be loaded from the `AUTH0_CLIENT_ID` environment variable.
   */
  clientId?: string;
  /**
   * The Auth0 client secret.
   *
   * If it's not specified, it will be loaded from the `AUTH0_CLIENT_SECRET` environment variable.
   */
  clientSecret?: string;
  /**
   * Additional parameters to send to the `/authorize` endpoint.
   */
  authorizationParameters?: AuthorizationParameters;
  /**
   * If enabled, the SDK will use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server.
   */
  pushedAuthorizationRequests?: boolean;
  /**
   * Private key for use with `private_key_jwt` clients.
   * This should be a string that is the contents of a PEM file or a CryptoKey.
   */
  clientAssertionSigningKey?: string | CryptoKey;
  /**
   * The algorithm used to sign the client assertion JWT.
   * Uses one of `token_endpoint_auth_signing_alg_values_supported` if not specified.
   * If the Authorization Server discovery document does not list `token_endpoint_auth_signing_alg_values_supported`
   * this property will be required.
   */
  clientAssertionSigningAlg?: string;

  // application configuration
  /**
   * The URL of your application (e.g.: `http://localhost:3000`).
   *
   * Can be a single URL string, or an array of allowed base URLs. When an array is
   * provided, the SDK validates the incoming request origin against the list and uses
   * the matching entry (allow-list mode). This is useful for multi-domain or preview
   * deployments where you want to restrict which origins are accepted.
   *
   * If it's not specified, it will be loaded from the `APP_BASE_URL` environment variable.
   * Multiple origins can be provided as a comma-separated string (e.g. `https://app.example.com,https://myapp.vercel.app`).
   * If neither is provided, the SDK will infer it from the request host at runtime.
   */
  appBaseUrl?: string | string[];
  /**
   * A 32-byte, hex-encoded secret used for encrypting cookies.
   *
   * If it's not specified, it will be loaded from the `AUTH0_SECRET` environment variable.
   */
  secret?: string;
  /**
   * The path to redirect the user to after successfully authenticating. Defaults to `/`.
   */
  signInReturnToPath?: string;

  // session configuration
  /**
   * Configure the session timeouts and whether to use rolling sessions or not.
   *
   * See [Session configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#session-configuration) for additional details.
   */
  session?: SessionConfiguration;

  // transaction cookie configuration
  /**
   * Configure the transaction cookie used to store the state of the authentication transaction.
   */
  transactionCookie?: TransactionCookieOptions;

  // logout configuration
  /**
   * Configure the logout strategy to use.
   *
   * - `'auto'` (default): Attempts OIDC RP-Initiated Logout first, falls back to `/v2/logout` if not supported
   * - `'oidc'`: Always uses OIDC RP-Initiated Logout (requires RP-Initiated Logout to be enabled)
   * - `'v2'`: Always uses the Auth0 `/v2/logout` endpoint (supports wildcards in allowed logout URLs)
   */
  logoutStrategy?: LogoutStrategy;

  /**
   * Configure whether to include id_token_hint in OIDC logout URLs.
   *
   * **Recommended (default)**: Set to `true` to include `id_token_hint` parameter.
   * Auth0 recommends using `id_token_hint` for secure logout as per the
   * OIDC specification.
   *
   * **Alternative approach**: Set to `false` if your application cannot securely
   * store ID tokens. When disabled, only `logout_hint` (session ID), `client_id`,
   * and `post_logout_redirect_uri` are sent.
   *
   *
   * @see https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0#oidc-logout-endpoint-parameters
   * @default true (recommended and backwards compatible)
   */
  includeIdTokenHintInOIDCLogoutUrl?: boolean;

  // hooks
  /**
   * A method to manipulate the session before persisting it.
   *
   * See [beforeSessionSaved](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#beforesessionsaved) for additional details
   */
  beforeSessionSaved?: BeforeSessionSavedHook;
  /**
   * A method to handle errors or manage redirects after attempting to authenticate.
   *
   * See [onCallback](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#oncallback) for additional details
   */
  onCallback?: OnCallbackHook;

  // provide a session store to persist sessions in your own data store
  /**
   * A custom session store implementation used to persist sessions to a data store.
   *
   * See [Database sessions](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#database-sessions) for additional details.
   */
  sessionStore?: SessionDataStore;

  /**
   * Configure the paths for the authentication routes.
   *
   * See [Custom routes](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#custom-routes) for additional details.
   */
  routes?: RoutesOptions;

  /**
   * Allow insecure requests to be made to the authorization server. This can be useful when testing
   * with a mock OIDC provider that does not support TLS, locally.
   * This option can only be used when NODE_ENV is not set to `production`.
   */
  allowInsecureRequests?: boolean;

  /**
   * Integer value for the HTTP timeout in milliseconds for authentication requests.
   * Defaults to `5000` ms.
   */
  httpTimeout?: number;

  /**
   * Boolean value to opt-out of sending the library name and version to your authorization server
   * via the `Auth0-Client` header. Defaults to `true`.
   */
  enableTelemetry?: boolean;

  /**
   * Boolean value to enable the `/auth/access-token` endpoint for use in the client app.
   *
   * Defaults to `true`.
   *
   * NOTE: Set this to `false` if your client does not need to directly interact with resource servers (Token Mediating Backend). This will be false for most apps.
   *
   * A security best practice is to disable this to avoid exposing access tokens to the client app.
   *
   * See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#name-token-mediating-backend
   */
  enableAccessTokenEndpoint?: boolean;

  /**
   * Number of seconds to refresh access tokens early when calling `getAccessToken`.
   * This is a server-side buffer applied to token expiration checks. For example,
   * with a buffer of 60 seconds, tokens expiring within the next minute will be
   * refreshed proactively when a refresh token is available.
   *
   * Defaults to `0` (no early refresh).
   */
  tokenRefreshBuffer?: number;

  /**
   * If true, the profile endpoint will return a 204 No Content response when the user is not authenticated
   * instead of returning a 401 Unauthorized response.
   *
   * Defaults to `false`.
   */
  noContentProfileResponseWhenUnauthenticated?: boolean;

  enableParallelTransactions?: boolean;

  /**
   * If true, the `/auth/connect` endpoint will be mounted to enable users to connect additional accounts.
   */
  enableConnectAccountEndpoint?: boolean;

  // DPoP Configuration
  /**
   * Enable DPoP (Demonstrating Proof-of-Possession) for enhanced OAuth 2.0 security.
   *
   * When enabled, the SDK will:
   * - Generate DPoP proofs for token requests and protected resource requests
   * - Bind access tokens cryptographically to the client's key pair
   * - Prevent token theft and replay attacks
   * - Handle DPoP nonce errors with automatic retry logic
   *
   * DPoP requires an ES256 key pair that can be provided via `dpopKeyPair` option
   * or loaded from environment variables `AUTH0_DPOP_PUBLIC_KEY` and `AUTH0_DPOP_PRIVATE_KEY`.
   *
   * @default false
   *
   * @example Enable DPoP with generated keys
   * ```typescript
   * import { generateKeyPair } from "oauth4webapi";
   *
   * const dpopKeyPair = await generateKeyPair("ES256");
   *
   * const auth0 = new Auth0Client({
   *   useDPoP: true,
   *   dpopKeyPair
   * });
   * ```
   *
   * @example Enable DPoP with environment variables
   * ```typescript
   * // .env.local
   * // AUTH0_DPOP_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."
   * // AUTH0_DPOP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."
   *
   * const auth0 = new Auth0Client({
   *   useDPoP: true
   *   // Keys loaded automatically from environment
   * });
   * ```
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc9449 | RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)}
   */
  useDPoP?: boolean;

  /**
   * ES256 key pair for DPoP proof generation.
   *
   * If not provided when `useDPoP` is true, the SDK will attempt to load keys from
   * environment variables `AUTH0_DPOP_PUBLIC_KEY` and `AUTH0_DPOP_PRIVATE_KEY`.
   * Keys must be in PEM format and use the P-256 elliptic curve.
   *
   * @example Provide key pair directly
   * ```typescript
   * import { generateKeyPair } from "oauth4webapi";
   *
   * const keyPair = await generateKeyPair("ES256");
   *
   * const auth0 = new Auth0Client({
   *   useDPoP: true,
   *   dpopKeyPair: keyPair
   * });
   * ```
   *
   * @example Load from files
   * ```typescript
   * import { importSPKI, importPKCS8 } from "jose";
   * import { readFileSync } from "fs";
   *
   * const publicKeyPem = readFileSync("dpop-public.pem", "utf8");
   * const privateKeyPem = readFileSync("dpop-private.pem", "utf8");
   *
   * const auth0 = new Auth0Client({
   *   useDPoP: true,
   *   dpopKeyPair: {
   *     publicKey: await importSPKI(publicKeyPem, "ES256"),
   *     privateKey: await importPKCS8(privateKeyPem, "ES256")
   *   }
   * });
   * ```
   *
   * @see {@link DpopKeyPair} for the key pair interface
   * @see {@link generateDpopKeyPair} for generating new key pairs
   */
  dpopKeyPair?: DpopKeyPair;

  /**
   * Configuration options for DPoP timing validation and retry behavior.
   *
   * These options control how the SDK validates DPoP proof timing and handles
   * nonce errors. Proper configuration is important for both security and reliability.
   *
   * @example Basic configuration
   * ```typescript
   * const auth0 = new Auth0Client({
   *   useDPoP: true,
   *   dpopOptions: {
   *     clockTolerance: 60,    // Allow 60 seconds clock difference
   *     clockSkew: 0,          // No clock adjustment needed
   *     retry: {
   *       delay: 200,          // 200ms delay before retry
   *       jitter: true         // Add randomness to prevent thundering herd
   *     }
   *   }
   * });
   * ```
   *
   * @example Environment variable configuration
   * ```bash
   * # .env.local
   * AUTH0_DPOP_CLOCK_SKEW=0
   * AUTH0_DPOP_CLOCK_TOLERANCE=30
   * AUTH0_RETRY_DELAY=100
   * AUTH0_RETRY_JITTER=true
   * ```
   *
   * @see {@link DpopOptions} for detailed option descriptions
   */
  dpopOptions?: DpopOptions;

  /**
   * MFA context TTL in seconds. Controls how long encrypted mfa_token remains valid.
   * Default: 300 (5 minutes, matching Auth0's mfa_token expiration)
   *
   * Can also be set via AUTH0_MFA_TOKEN_TTL environment variable.
   *
   * @example
   * ```typescript
   * const auth0 = new Auth0Client({
   *   mfaTokenTtl: 600 // 10 minutes
   * });
   * ```
   */
  mfaTokenTtl?: number;

  /**
   * Configuration for the OIDC discovery metadata cache.
   * Controls TTL and maximum cached issuers for MCD resolver mode.
   * Also applies in static mode (single cached entry).
   *
   * @see {@link DiscoveryCacheOptions}
   * @see [MCD Examples](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#multiple-custom-domains-mcd)
   */
  discoveryCache?: DiscoveryCacheOptions;
}

/**
 * The incoming request type accepted by `getSession()`, `getAccessToken()`, and similar methods
 * in the Pages Router. Pass `req` from `getServerSideProps` or an API route handler.
 *
 * @group Server
 * @title Pages Router Request
 * @order 161
 */
export type PagesRouterRequest = IncomingMessage | NextApiRequest;

/**
 * The response type accepted by `getSession()`, `getAccessToken()`, and `updateSession()` methods
 * in the Pages Router. Pass `res` from `getServerSideProps` or an API route handler.
 *
 * @group Server
 * @title Pages Router Response
 * @order 162
 */
export type PagesRouterResponse =
  | ServerResponse<IncomingMessage>
  | NextApiResponse;

/**
 * The main server-side Auth0 client. Create one instance and share it across your entire app.
 *
 * The recommended pattern is to create the instance in `lib/auth0.ts` and import it wherever needed:
 * Server Components, Server Actions, Route Handlers, middleware, and Pages Router API routes.
 *
 * **Setup using environment variables (recommended):**
 *
 * Set these in `.env.local`:
 * ```
 * AUTH0_DOMAIN=your-tenant.us.auth0.com
 * AUTH0_CLIENT_ID=your_client_id
 * AUTH0_CLIENT_SECRET=your_client_secret
 * AUTH0_SECRET=a_32_byte_hex_secret
 * APP_BASE_URL=http://localhost:3000
 * ```
 *
 * Then create the client with no arguments:
 * ```ts
 * // lib/auth0.ts
 * import { Auth0Client } from '@auth0/nextjs-auth0/server';
 *
 * export const auth0 = new Auth0Client();
 * ```
 *
 * **Setup passing options directly:**
 * ```ts
 * export const auth0 = new Auth0Client({
 *   domain:       'your-tenant.us.auth0.com',
 *   clientId:     'YOUR_CLIENT_ID',
 *   clientSecret: 'YOUR_CLIENT_SECRET',
 *   secret:       'YOUR_32_BYTE_SECRET',
 *   appBaseUrl:   'http://localhost:3000',
 * });
 * ```
 *
 * **Built-in routes (served by `middleware()`):**
 *
 * Once you mount `auth0.middleware(req)` in `middleware.ts`, the following routes are handled automatically:
 *
 * | Route | Description |
 * |---|---|
 * | `GET /auth/login` | Redirects the user to Auth0 to log in. Add `?returnTo=/path` to control the post-login redirect. |
 * | `GET /auth/logout` | Logs the user out and clears the session. |
 * | `GET /auth/callback` | Handles the OAuth callback from Auth0 after login. |
 * | `GET /auth/profile` | Returns the logged-in user's profile as JSON. |
 * | `GET /auth/access-token` | Returns a fresh access token for the current session as JSON. |
 * | `POST /auth/backchannel-logout` | Handles Auth0 backchannel logout notifications. |
 *
 * To trigger login from a link or button:
 * ```tsx
 * <a href="/auth/login">Log in</a>
 * <a href="/auth/login?returnTo=/dashboard">Log in and go to dashboard</a>
 * <a href="/auth/logout">Log out</a>
 * ```
 *
 * Route paths can be customized via the `routes` option in `Auth0ClientOptions`.
 *
 * @group Initialisation
 * @title Auth0 Client
 * @order 1
 */
export class Auth0Client {
  private transactionStore: TransactionStore;
  private sessionStore: AbstractSessionStore;
  private provider: AuthClientProvider;
  private routes: Routes;
  private _mfa?: ServerMfaClient;
  #options: Auth0ClientOptions;

  constructor(options: Auth0ClientOptions = {}) {
    this.#options = options;

    // Extract and validate required options
    const {
      domain,
      clientId,
      clientSecret,
      appBaseUrl,
      secret,
      clientAssertionSigningKey
    } = this.validateAndExtractRequiredOptions(options);

    const clientAssertionSigningAlg =
      options.clientAssertionSigningAlg ||
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_ALG;

    // Early warning if DPoP is enabled but no keypair (doesn't require crypto)
    if (options.useDPoP && !options.dpopKeyPair) {
      const privateKeyEnv = process.env.AUTH0_DPOP_PRIVATE_KEY;
      const publicKeyEnv = process.env.AUTH0_DPOP_PUBLIC_KEY;
      const hasBothKeys = Boolean(privateKeyEnv && publicKeyEnv);

      if (!hasBothKeys) {
        console.warn(
          "WARNING: useDPoP is set to true but dpopKeyPair is not provided. " +
            "DPoP will not be used and protected requests will use bearer authentication instead. " +
            "To enable DPoP, provide a dpopKeyPair in the Auth0Client options or set " +
            "AUTH0_DPOP_PUBLIC_KEY and AUTH0_DPOP_PRIVATE_KEY environment variables."
        );
      }
      // Note: If both env vars ARE present, validation happens lazily on first DPoP operation
      // This prevents crypto module from being bundled when useDPoP=false
    }

    // Resolve MFA token TTL from options or environment variable
    const mfaTokenTtl = this.resolveMfaTokenTtl(
      options.mfaTokenTtl,
      process.env.AUTH0_MFA_TOKEN_TTL
    );

    const tokenRefreshBufferOption = options.tokenRefreshBuffer;
    if (tokenRefreshBufferOption != null) {
      if (
        typeof tokenRefreshBufferOption !== "number" ||
        !Number.isFinite(tokenRefreshBufferOption) ||
        tokenRefreshBufferOption < 0
      ) {
        throw new TypeError(
          "tokenRefreshBuffer must be a non-negative number of seconds."
        );
      }
    }
    const tokenRefreshBuffer = tokenRefreshBufferOption ?? 0;

    // Auto-detect base path for cookie configuration
    const basePath = process.env.NEXT_PUBLIC_BASE_PATH;

    // Session cookie secure can be configured via options or AUTH0_COOKIE_SECURE.
    const envCookieSecure = process.env.AUTH0_COOKIE_SECURE;
    const sessionSecureExplicit =
      options.session?.cookie?.secure ??
      (envCookieSecure !== undefined ? envCookieSecure === "true" : undefined);

    const sessionCookieOptions: SessionCookieOptions = {
      name: options.session?.cookie?.name ?? "__session",
      secure: sessionSecureExplicit ?? false,
      sameSite:
        options.session?.cookie?.sameSite ??
        (process.env.AUTH0_COOKIE_SAME_SITE as "lax" | "strict" | "none") ??
        "lax",
      path:
        options.session?.cookie?.path ??
        process.env.AUTH0_COOKIE_PATH ??
        basePath ??
        "/",
      transient:
        options.session?.cookie?.transient ??
        process.env.AUTH0_COOKIE_TRANSIENT === "true",
      domain: options.session?.cookie?.domain ?? process.env.AUTH0_COOKIE_DOMAIN
    };

    // Transaction cookies only support secure via options (no env var).
    const transactionSecureExplicit = options.transactionCookie?.secure;
    const transactionCookieOptions: TransactionCookieOptions = {
      prefix: options.transactionCookie?.prefix ?? "__txn_",
      secure: transactionSecureExplicit ?? false,
      sameSite: options.transactionCookie?.sameSite ?? "lax",
      path: options.transactionCookie?.path ?? basePath ?? "/",
      maxAge: options.transactionCookie?.maxAge ?? 3600,
      domain:
        options.transactionCookie?.domain ?? process.env.AUTH0_COOKIE_DOMAIN
    };

    if (appBaseUrl) {
      const usesHttps = Array.isArray(appBaseUrl)
        ? appBaseUrl.every((url) => new URL(url).protocol === "https:")
        : new URL(appBaseUrl).protocol === "https:";

      // Only enforce secure cookies when the configured base URL(s) are all https.
      if (usesHttps) {
        sessionCookieOptions.secure = true;
        transactionCookieOptions.secure = true;
      }
    } else if (process.env.NODE_ENV === "production") {
      // No appBaseUrl is configured, so the SDK relies on the request host at runtime.
      // In production we require secure cookies for this dynamic mode (and fail fast if
      // a cookie is explicitly marked insecure) to avoid shipping non-secure defaults.
      if (sessionSecureExplicit === false) {
        throw new InvalidConfigurationError(
          "Session cookies must be marked secure in production when appBaseUrl is not configured. Set AUTH0_COOKIE_SECURE=true or session.cookie.secure=true."
        );
      }

      if (transactionSecureExplicit === false) {
        throw new InvalidConfigurationError(
          "Transaction cookies must be marked secure in production when appBaseUrl is not configured. Set transactionCookie.secure=true."
        );
      }

      sessionCookieOptions.secure = true;
      transactionCookieOptions.secure = true;
    } else if (
      process.env.NODE_ENV === "development" &&
      (sessionSecureExplicit === false || transactionSecureExplicit === false)
    ) {
      // Warn during development when dynamic base URL resolution is combined with
      // explicitly insecure cookies, since production will reject this configuration.
      console.warn(
        "'appBaseUrl' is not configured and cookies are explicitly marked insecure. This is allowed in development, but will throw in production. Configure appBaseUrl or set secure=true for session/transaction cookies."
      );
    }

    this.routes = {
      login: process.env.NEXT_PUBLIC_LOGIN_ROUTE || "/auth/login",
      logout: "/auth/logout",
      callback: "/auth/callback",
      backChannelLogout: "/auth/backchannel-logout",
      profile: process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile",
      accessToken:
        process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token",
      connectAccount: "/auth/connect",
      mfaAuthenticators:
        process.env.NEXT_PUBLIC_MFA_AUTHENTICATORS_ROUTE ||
        "/auth/mfa/authenticators",
      mfaChallenge:
        process.env.NEXT_PUBLIC_MFA_CHALLENGE_ROUTE || "/auth/mfa/challenge",
      mfaVerify: process.env.NEXT_PUBLIC_MFA_VERIFY_ROUTE || "/auth/mfa/verify",
      mfaEnroll: process.env.NEXT_PUBLIC_MFA_ENROLL_ROUTE || "/auth/mfa/enroll",
      // deleteAuthenticator uses mfaAuthenticators route with DELETE method
      ...options.routes
    };

    this.transactionStore = new TransactionStore({
      secret,
      cookieOptions: transactionCookieOptions,
      enableParallelTransactions: options.enableParallelTransactions ?? true
    });

    this.sessionStore = options.sessionStore
      ? new StatefulSessionStore({
          ...options.session,
          secret,
          store: options.sessionStore,
          cookieOptions: sessionCookieOptions
        })
      : new StatelessSessionStore({
          ...options.session,
          secret,
          cookieOptions: sessionCookieOptions
        });

    // Create discovery cache for the provider
    const discoveryCache = new DiscoveryCache(options.discoveryCache);

    // When AUTH0_DOMAIN is not available at module evaluation time (e.g. during a
    // Next.js standalone build that injects env vars only at runtime), `domain` will
    // be undefined. Passing undefined to AuthClientProvider causes it to throw
    // immediately in the constructor, which breaks the build.
    //
    // Work around this by converting a missing domain into a DomainResolver that
    // reads AUTH0_DOMAIN lazily on the first request. If the env var is still absent
    // at request time, the resolver will throw with a clear error message.
    //
    // If domain is already a string or a DomainResolver function, it is used as-is.
    const domainForProvider: string | DomainResolver =
      domain ||
      (() => {
        const runtimeDomain = process.env.AUTH0_DOMAIN;
        if (!runtimeDomain) {
          throw new InvalidConfigurationError(
            "Missing: domain: Set AUTH0_DOMAIN env var or pass domain in options."
          );
        }
        return runtimeDomain;
      });

    // Create provider that manages AuthClient instances
    // Note: We defer the provider reference in the factory to avoid circular reference during construction.
    // The factory captures 'this' by reference, and will read this.provider when called later (not during construction).
    this.provider = new AuthClientProvider({
      domain: domainForProvider,
      createAuthClient: (domainForClient) => {
        return new AuthClient({
          transactionStore: this.transactionStore,
          sessionStore: this.sessionStore,

          domain: domainForClient,
          clientId,
          clientSecret,
          clientAssertionSigningKey,
          clientAssertionSigningAlg,
          authorizationParameters: options.authorizationParameters,
          pushedAuthorizationRequests: options.pushedAuthorizationRequests,

          appBaseUrl,
          secret,
          signInReturnToPath: options.signInReturnToPath,
          logoutStrategy: options.logoutStrategy,
          includeIdTokenHintInOIDCLogoutUrl:
            options.includeIdTokenHintInOIDCLogoutUrl,

          beforeSessionSaved: options.beforeSessionSaved,
          onCallback: options.onCallback,

          routes: this.routes,

          allowInsecureRequests: options.allowInsecureRequests,
          httpTimeout: options.httpTimeout,
          enableTelemetry: options.enableTelemetry,
          enableAccessTokenEndpoint: options.enableAccessTokenEndpoint,
          noContentProfileResponseWhenUnauthenticated:
            options.noContentProfileResponseWhenUnauthenticated,
          enableConnectAccountEndpoint: options.enableConnectAccountEndpoint,
          tokenRefreshBuffer,
          useDPoP: options.useDPoP || false,
          dpopKeyPair: options.dpopKeyPair,
          dpopOptions: options.dpopOptions,
          mfaTokenTtl,

          discoveryCache,
          provider: this.provider
        });
      }
    });

    // Update provider references in any already-created AuthClients (static mode)
    // This is needed because the factory in static mode is called during AuthClientProvider construction,
    // before this.provider is fully assigned. The closure captures 'this', so by this point it will be valid.
    const staticClient = this.provider.getAuthClientForStaticMode();
    if (staticClient) {
      staticClient.provider = this.provider;
    }
  }

  /**
   * Handles all Auth0 routes (login, logout, callback, profile, access-token) from Next.js middleware.
   * Call this from `middleware.ts` at the root of your project so every auth route is served automatically.
   *
   * @param req - The incoming Next.js request from middleware.
   *
   * @returns A `NextResponse` handled by the matching auth route, or a passthrough response for all other routes.
   *
   * @throws `DomainResolutionError` (code `"domain_resolution_error"`) if a `DomainResolver` function throws or returns an invalid value. Only applies when using Multiple Custom Domains.
   * @throws `DomainValidationError` (code `"domain_validation_error"`) if the resolved domain is an IP address, localhost, or contains a path/port. Only applies when using Multiple Custom Domains.
   *
   * @example
   * ```ts
   * // middleware.ts
   * import type { NextRequest } from 'next/server';
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function middleware(req: NextRequest) {
   *   return await auth0.middleware(req);
   * }
   *
   * export const config = {
   *   matcher: [
   *     // Skip Next.js internals and static files, always run for API routes and pages
   *     '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
   *   ],
   * };
   * ```
   *
   */
  async middleware(req: Request | NextRequest): Promise<NextResponse> {
    const nextReq = toNextRequest(req);
    const authClient = await this.provider.forRequest(
      nextReq.headers,
      nextReq.nextUrl
    );
    return authClient.handler.bind(authClient)(nextReq);
  }

  /**
   * Returns the active session, or `null` if the user is not logged in.
   *
   * **App Router** (Server Components, Server Actions, Route Handlers): call with no arguments.
   * The SDK reads the session cookie via Next.js `cookies()` automatically.
   *
   * **Pages Router / middleware**: pass `req` so the SDK can read cookies from the request.
   *
   * The session contains:
   * - `user`: the logged-in user's profile (`sub`, `name`, `email`, `picture`, etc.)
   * - `tokenSet`: the current access token, its expiry, and scope
   *
   * @param req - Pages Router or middleware request. Omit in App Router.
   *
   * @returns The session object, or `null` if no active session exists.
   *
   * @throws `SessionDomainMismatchError` (code `"session_domain_mismatch"`) if the session was created on a different domain. Treat this the same as a missing session. Only applies when using Multiple Custom Domains.
   * @throws `IssuerValidationError` (code `"issuer_validation_error"`) if the ID token issuer does not match the resolved domain. Only applies when using Multiple Custom Domains.
   *
   * @example App Router page
   * ```ts
   * // app/dashboard/page.tsx
   * import { redirect } from 'next/navigation';
   * import { auth0 } from '@/lib/auth0';
   *
   * export default async function Dashboard() {
   *   const session = await auth0.getSession();
   *   if (!session) redirect('/auth/login');
   *
   *   return <h1>Welcome, {session.user.name}</h1>;
   * }
   * ```
   *
   * @example Pages Router API route
   * ```ts
   * // pages/api/me.ts
   * import type { NextApiRequest, NextApiResponse } from 'next';
   * import { auth0 } from '@/lib/auth0';
   *
   * export default async function handler(req: NextApiRequest, res: NextApiResponse) {
   *   const session = await auth0.getSession(req);
   *   if (!session) return res.status(401).json({ error: 'Not authenticated' });
   *   res.json({ user: session.user });
   * }
   * ```
   *
   */
  async getSession(): Promise<SessionData | null>;
  async getSession(
    req: PagesRouterRequest | NextRequest
  ): Promise<SessionData | null>;

  /** @internal */
  async getSession(
    req?: Request | PagesRouterRequest | NextRequest
  ): Promise<SessionData | null> {
    const { authClient, normalizedReq } = await this.resolveRequestContext(req);

    // extract cookies
    let reqCookies:
      | RequestCookies
      | import("./cookies.js").ReadonlyRequestCookies;
    if (normalizedReq) {
      reqCookies =
        normalizedReq instanceof NextRequest
          ? normalizedReq.cookies
          : this.createRequestCookies(normalizedReq);
    } else {
      reqCookies = await cookies();
    }

    const { error, session } =
      await authClient.getSessionWithDomainCheck(reqCookies);
    if (error) throw error;
    return session;
  }

  /**
   * Fetches session using an already-resolved AuthClient, avoiding double resolver invocation.
   * @internal
   */
  private async getSessionFromAuthClient(
    authClient: AuthClient,
    req?: PagesRouterRequest | NextRequest
  ): Promise<SessionData | null> {
    let reqCookies:
      | RequestCookies
      | import("./cookies.js").ReadonlyRequestCookies;
    if (req) {
      reqCookies =
        req instanceof NextRequest
          ? req.cookies
          : this.createRequestCookies(req);
    } else {
      reqCookies = await cookies();
    }
    const { error, session } =
      await authClient.getSessionWithDomainCheck(reqCookies);
    if (error) throw error;
    return session;
  }

  /**
   * Returns the access token for the current user, refreshing it automatically if expired.
   *
   * **App Router** (Server Components, Server Actions, Route Handlers): call with no `req`/`res`.
   * The SDK reads cookies automatically. Note: if a token refresh happens inside a Server Component,
   * the updated token cannot be persisted because Server Components cannot set cookies. Use middleware
   * with `getAccessToken(req, res)` when persistence after refresh is required.
   *
   * **Pages Router / middleware**: pass both `req` and `res` so the refreshed token can be
   * written back to the session cookie.
   *
   * @param req - Pages Router or middleware request. Omit in App Router.
   * @param res - Pages Router or middleware response. Omit in App Router.
   * @param options.refresh - Force a refresh even if the token has not expired yet.
   * @param options.audience - API identifier the token should be issued for.
   * @param options.scope - Space-separated scopes to request.
   *
   * @returns `{ token, expiresAt, scope?, token_type?, audience? }`.
   *
   * @throws `AccessTokenError` (code `"missing_session"`) if the user is not authenticated.
   * @throws `AccessTokenError` (code `"missing_refresh_token"`) if the token is expired and there is no refresh token.
   * @throws `AccessTokenError` (code `"failed_to_refresh_token"`) if Auth0 rejects the refresh attempt.
   * @throws `MfaRequiredError` (code `"mfa_required"`) if Auth0 requires MFA step-up before issuing the token. Catch this and use `err.mfa_token` to drive the MFA flow via `auth0.mfa`. The `err.mfa_requirements` property lists available challenge types and enrollment options.
   *
   * @example App Router route handler
   * ```ts
   * // app/api/data/route.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function GET() {
   *   const { token } = await auth0.getAccessToken();
   *   const res = await fetch('https://api.example.com/data', {
   *     headers: { Authorization: `Bearer ${token}` },
   *   });
   *   return Response.json(await res.json());
   * }
   * ```
   *
   * @example Pages Router API route
   * ```ts
   * // pages/api/data.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export default async function handler(req, res) {
   *   const { token } = await auth0.getAccessToken(req, res);
   *   const apiRes = await fetch('https://api.example.com/data', {
   *     headers: { Authorization: `Bearer ${token}` },
   *   });
   *   res.json(await apiRes.json());
   * }
   * ```
   *
   */
  async getAccessToken(options?: GetAccessTokenOptions): Promise<{
    token: string;
    expiresAt: number;
    scope?: string;
    token_type?: string;
    audience?: string;
  }>;
  async getAccessToken(
    req: PagesRouterRequest | NextRequest,
    res: PagesRouterResponse | NextResponse,
    options?: GetAccessTokenOptions
  ): Promise<{
    token: string;
    expiresAt: number;
    scope?: string;
    token_type?: string;
    audience?: string;
  }>;

  /** @internal */
  async getAccessToken(
    arg1?: PagesRouterRequest | NextRequest | GetAccessTokenOptions,
    arg2?: PagesRouterResponse | NextResponse,
    arg3?: GetAccessTokenOptions
  ): Promise<{
    token: string;
    expiresAt: number;
    scope?: string;
    token_type?: string;
    audience?: string;
  }> {
    const defaultOptions: GetAccessTokenOptions = {
      refresh: false
    };

    let req: PagesRouterRequest | NextRequest | undefined = undefined;
    let res: PagesRouterResponse | NextResponse | undefined = undefined;
    let options: GetAccessTokenOptions = {};

    // Determine which overload was called based on arguments
    if (
      arg1 &&
      (arg1 instanceof Request || typeof (arg1 as any).headers === "object")
    ) {
      // Case: getAccessToken(req, res, options?)
      req = arg1 as PagesRouterRequest | NextRequest;
      res = arg2; // arg2 must be Response if arg1 is Request
      // Merge provided options (arg3) with defaults
      options = { ...defaultOptions, ...(arg3 ?? {}) };
      if (!res) {
        throw new TypeError(
          "getAccessToken(req, res): The 'res' argument is missing. Both 'req' and 'res' must be provided together for Pages Router or middleware usage."
        );
      }
    } else {
      // Case: getAccessToken(options?) or getAccessToken()
      // arg1 (if present) must be options, arg2 and arg3 must be undefined.
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "getAccessToken: Invalid arguments. Valid signatures are getAccessToken(), getAccessToken(options), or getAccessToken(req, res, options)."
        );
      }
      // Merge provided options (arg1) with defaults
      options = {
        ...defaultOptions,
        ...((arg1 as GetAccessTokenOptions) ?? {})
      };
    }

    return this.executeGetAccessToken(req, res, options);
  }

  /**
   * Core implementation of getAccessToken that performs the actual token retrieval.
   * This is separated to enable request coalescing via the cache.
   */
  private async executeGetAccessToken(
    req: PagesRouterRequest | NextRequest | undefined,
    res: PagesRouterResponse | NextResponse | undefined,
    options: GetAccessTokenOptions
  ): Promise<{
    token: string;
    expiresAt: number;
    scope?: string;
    token_type?: string;
    audience?: string;
  }> {
    const { authClient, normalizedReq } = await this.resolveRequestContext(req);

    const session = await this.getSessionFromAuthClient(
      authClient,
      normalizedReq
    );

    if (!session) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      );
    }

    const [error, getTokenSetResponse] = await authClient.getTokenSet(
      session,
      options
    );
    if (error) {
      // For MFA required errors, save session with MFA context before throwing
      // Note: getTokenSet mutates session.mfa by reference when MFA is required
      if (error instanceof MfaRequiredError) {
        await this.saveToSession(session, req, res);
      }
      throw error;
    }
    const { tokenSet, idTokenClaims } = getTokenSetResponse;
    // update the session with the new token set, if necessary
    const sessionChanges = getSessionChangesAfterGetAccessToken(
      session,
      tokenSet,
      {
        scope: this.#options.authorizationParameters?.scope ?? DEFAULT_SCOPES,
        audience: this.#options.authorizationParameters?.audience
      }
    );

    if (sessionChanges) {
      if (idTokenClaims) {
        session.user = idTokenClaims as User;
      }
      // call beforeSessionSaved callback if present
      // if not then filter id_token claims with default rules
      const finalSession = await authClient.finalizeSession(
        { ...session, ...sessionChanges },
        tokenSet.idToken
      );
      await this.saveToSession(finalSession, req, res);
    }

    return {
      token: tokenSet.accessToken,
      scope: tokenSet.scope,
      expiresAt: tokenSet.expiresAt,
      token_type: tokenSet.token_type,
      audience: tokenSet.audience
    };
  }

  /**
   * Returns an access token scoped to a specific social connection (e.g. Google, GitHub).
   * Use this when you need to call a third-party provider API on behalf of the logged-in user.
   *
   * **App Router**: call with `options` only. The SDK reads cookies automatically.
   *
   * **Pages Router / middleware**: pass `req` and `res` as additional arguments so the refreshed
   * token can be written back to the session cookie.
   *
   * **Prerequisite:** The connection must be enabled on your Auth0 application and the user must
   * have authorized it during login.
   *
   * @param options.connection - The connection name, e.g. `"google-oauth2"` or `"github"`.
   * @param req - Pages Router or middleware request. Omit in App Router.
   * @param res - Pages Router or middleware response. Omit in App Router.
   *
   * @returns `{ token, expiresAt, scope? }`.
   *
   * @throws `AccessTokenForConnectionError` (code `"missing_session"`) if the user is not authenticated.
   * @throws `AccessTokenForConnectionError` (code `"missing_refresh_token"`) if no refresh token is available to exchange.
   * @throws `AccessTokenForConnectionError` (code `"failed_to_exchange_refresh_token"`) if Auth0 rejects the token exchange.
   *
   * @example
   * ```ts
   * // app/api/calendar/route.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function GET() {
   *   const { token } = await auth0.getAccessTokenForConnection({
   *     connection: 'google-oauth2',
   *   });
   *
   *   const res = await fetch('https://www.googleapis.com/calendar/v3/calendars/primary/events', {
   *     headers: { Authorization: `Bearer ${token}` },
   *   });
   *   return Response.json(await res.json());
   * }
   * ```
   *
   */
  async getAccessTokenForConnection(
    options: AccessTokenForConnectionOptions
  ): Promise<{ token: string; expiresAt: number }>;
  async getAccessTokenForConnection(
    options: AccessTokenForConnectionOptions,
    req: PagesRouterRequest | NextRequest | Request | undefined,
    res: PagesRouterResponse | NextResponse | undefined
  ): Promise<{ token: string; expiresAt: number }>;

  /** @internal */
  async getAccessTokenForConnection(
    options: AccessTokenForConnectionOptions,
    req?: PagesRouterRequest | NextRequest | Request,
    res?: PagesRouterResponse | NextResponse
  ): Promise<{ token: string; expiresAt: number; scope?: string }> {
    const { authClient, normalizedReq } = await this.resolveRequestContext(req);

    const session = await this.getSessionFromAuthClient(
      authClient,
      normalizedReq
    );

    if (!session) {
      throw new AccessTokenForConnectionError(
        AccessTokenForConnectionErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      );
    }

    // Find the connection token set in the session
    const existingTokenSet = session.connectionTokenSets?.find(
      (tokenSet) => tokenSet.connection === options.connection
    );

    const [error, retrievedTokenSet] = await authClient.getConnectionTokenSet(
      session.tokenSet,
      existingTokenSet,
      options
    );

    if (error !== null) {
      throw error;
    }

    // If we didn't have a corresponding connection token set in the session
    // or if the one we have in the session does not match the one we received
    // We want to update the store incase we retrieved a token set.
    if (
      retrievedTokenSet &&
      (!existingTokenSet ||
        retrievedTokenSet.accessToken !== existingTokenSet.accessToken ||
        retrievedTokenSet.expiresAt !== existingTokenSet.expiresAt ||
        retrievedTokenSet.scope !== existingTokenSet.scope)
    ) {
      let tokenSets;

      // If we already had the connection token set in the session
      // we need to update the item in the array
      // If not, we need to add it.
      if (existingTokenSet) {
        tokenSets = session.connectionTokenSets?.map((tokenSet) =>
          tokenSet.connection === options.connection
            ? retrievedTokenSet
            : tokenSet
        );
      } else {
        tokenSets = [...(session.connectionTokenSets || []), retrievedTokenSet];
      }

      await this.saveToSession(
        {
          ...session,
          connectionTokenSets: tokenSets
        },
        normalizedReq,
        res
      );
    }

    return {
      token: retrievedTokenSet.accessToken,
      scope: retrievedTokenSet.scope,
      expiresAt: retrievedTokenSet.expiresAt
    };
  }

  /**
   * Exchanges an external token for Auth0 tokens using Custom Token Exchange (RFC 8693).
   *
   * This is a server-only method. It does not create or modify the user's session; the returned
   * tokens are for the caller to use directly.
   *
   * @param options.subjectToken - The external token to exchange.
   * @param options.subjectTokenType - The type URI identifying the token, e.g. `"urn:acme:legacy-token"`.
   * @param options.audience - The API identifier the resulting access token should be issued for.
   * @param options.scope - Space-separated scopes to request.
   *
   * @returns The exchange response with `accessToken` and optionally `idToken` and `refreshToken`.
   *
   * @throws `CustomTokenExchangeError` (code `"missing_subject_token"`) if `subjectToken` is empty.
   * @throws `CustomTokenExchangeError` (code `"invalid_subject_token_type"`) if `subjectTokenType` is not a valid URI.
   * @throws `CustomTokenExchangeError` (code `"missing_actor_token_type"`) if `actorToken` is provided without `actorTokenType`.
   * @throws `CustomTokenExchangeError` (code `"exchange_failed"`) if Auth0 rejects the exchange.
   *
   * @example
   * ```ts
   * // app/api/exchange/route.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function POST(req: Request) {
   *   const { legacyToken } = await req.json();
   *
   *   const result = await auth0.customTokenExchange({
   *     subjectToken: legacyToken,
   *     subjectTokenType: 'urn:acme:legacy-token',
   *     audience: 'https://api.example.com',
   *   });
   *
   *   return Response.json({ accessToken: result.accessToken });
   * }
   * ```
   *
   */
  async customTokenExchange(
    options: CustomTokenExchangeOptions
  ): Promise<CustomTokenExchangeResponse> {
    const reqHeaders = await getHeaders();
    const authClient = await this.provider.forRequest(reqHeaders, undefined);

    const [error, response] = await authClient.customTokenExchange(options);

    if (error !== null) {
      throw error;
    }

    return response;
  }

  /**
   * Server-side MFA client. Access this when `getAccessToken()` throws a `MfaRequiredError`
   * and you need to drive the MFA challenge-response flow from the server.
   *
   * Methods:
   * - `getAuthenticators({ mfaToken })`: list the user's enrolled MFA factors. Throws `MfaGetAuthenticatorsError` on failure.
   * - `challenge({ mfaToken, challengeType, authenticatorId? })`: initiate a challenge. Throws `MfaChallengeError` on failure.
   * - `verify({ mfaToken, otp? | oobCode+bindingCode? | recoveryCode? })`: complete the challenge. Throws `MfaVerifyError` (code `"invalid_grant"`) on wrong code.
   * - `enroll({ mfaToken, authenticatorTypes, ... })`: enroll a new factor. Throws `MfaEnrollmentError` on failure.
   *
   * All `auth0.mfa` methods throw `MfaTokenExpiredError` (code `"mfa_token_expired"`) if the MFA token has expired,
   * and `MfaTokenInvalidError` (code `"mfa_token_invalid"`) if the token is malformed or encrypted with a different secret.
   *
   * @example
   * ```ts
   * // app/api/token/route.ts
   * import { auth0 } from '@/lib/auth0';
   * import { MfaRequiredError } from '@auth0/nextjs-auth0/server';
   *
   * export async function GET() {
   *   try {
   *     const { token } = await auth0.getAccessToken({ audience: 'https://api.example.com' });
   *     return Response.json({ token });
   *   } catch (err) {
   *     if (err instanceof MfaRequiredError) {
   *       const factors = await auth0.mfa.getAuthenticators({ mfaToken: err.mfa_token });
   *       const challenge = await auth0.mfa.challenge({
   *         mfaToken: err.mfa_token,
   *         challengeType: 'otp',
   *         authenticatorId: factors[0].id,
   *       });
   *       return Response.json({ mfaRequired: true, challenge });
   *     }
   *     throw err;
   *   }
   * }
   * ```
   *
   */
  get mfa(): ServerMfaClient {
    if (!this._mfa) {
      this._mfa = new ServerMfaClient(this.provider);
    }
    return this._mfa;
  }

  /**
   * Overwrites the current user's session. Throws if no session exists.
   *
   * **App Router** (Server Actions, Route Handlers): pass the updated `session` object only.
   * The SDK writes the new session cookie automatically.
   *
   * **Pages Router / middleware**: pass `req`, `res`, and the updated `session` so the SDK
   * can write the cookie to the response.
   *
   * @param session - The updated session data. Include the full session shape (spread existing and override fields).
   * @param req - Pages Router or middleware request. Omit in App Router.
   * @param res - Pages Router or middleware response. Omit in App Router.
   *
   * @throws `Error` if the user is not authenticated.
   *
   * @example App Router Server Action
   * ```ts
   * // app/actions/update-name.ts
   * 'use server';
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function updateName(name: string) {
   *   const session = await auth0.getSession();
   *   if (!session) throw new Error('Not authenticated');
   *
   *   await auth0.updateSession({
   *     ...session,
   *     user: { ...session.user, name },
   *   });
   * }
   * ```
   *
   * @example Pages Router API route
   * ```ts
   * // pages/api/update-name.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export default async function handler(req, res) {
   *   const session = await auth0.getSession(req);
   *   if (!session) return res.status(401).end();
   *
   *   await auth0.updateSession(req, res, {
   *     ...session,
   *     user: { ...session.user, name: req.body.name },
   *   });
   *   res.json({ ok: true });
   * }
   * ```
   *
   */
  async updateSession(
    req: PagesRouterRequest | NextRequest | Request,
    res: PagesRouterResponse | NextResponse | Response,
    session: SessionData
  ): Promise<void>;
  async updateSession(session: SessionData): Promise<void>;

  /** @internal */
  async updateSession(
    reqOrSession: PagesRouterRequest | NextRequest | Request | SessionData,
    res?: PagesRouterResponse | NextResponse | Response,
    sessionData?: SessionData
  ) {
    // Normalize plain Request (Next 16 Node runtime) to NextRequest
    if (
      reqOrSession instanceof Request &&
      !(reqOrSession instanceof NextRequest)
    ) {
      reqOrSession = toNextRequest(reqOrSession);
    }

    // Normalize plain Response (Next 16 Node runtime) to NextResponse
    if (res && res instanceof Response && !(res instanceof NextResponse)) {
      res = toNextResponse(res);
    }

    if (!res) {
      // app router: Server Actions, Route Handlers
      const existingSession = await this.getSession();

      if (!existingSession) {
        throw new Error("The user is not authenticated.");
      }

      const updatedSession = reqOrSession as SessionData;
      if (!updatedSession) {
        throw new Error("The session data is missing.");
      }

      await this.sessionStore.set(await cookies(), await cookies(), {
        ...updatedSession,
        internal: {
          ...existingSession.internal
        }
      });
    } else {
      const req = reqOrSession as PagesRouterRequest | NextRequest;

      if (!sessionData) {
        throw new Error("The session data is missing.");
      }

      if (req instanceof NextRequest && res instanceof NextResponse) {
        // middleware usage
        const existingSession = await this.getSession(req);

        if (!existingSession) {
          throw new Error("The user is not authenticated.");
        }

        await this.sessionStore.set(req.cookies, res.cookies, {
          ...sessionData,
          internal: {
            ...existingSession.internal
          }
        });
      } else {
        // pages router usage
        const existingSession = await this.getSession(
          req as PagesRouterRequest
        );

        if (!existingSession) {
          throw new Error("The user is not authenticated.");
        }

        const resHeaders = new Headers();
        const resCookies = new ResponseCookies(resHeaders);
        const updatedSession = sessionData as SessionData;
        const reqCookies = this.createRequestCookies(req as PagesRouterRequest);
        const pagesRouterRes = res as PagesRouterResponse;

        await this.sessionStore.set(reqCookies, resCookies, {
          ...updatedSession,
          internal: {
            ...existingSession.internal
          }
        });

        // Handle multiple set-cookie headers properly
        // resHeaders.entries() yields each set-cookie header separately,
        // but res.setHeader() overwrites previous values. We need to collect
        // all set-cookie values and set them as an array.
        // Note: Per the Web API specification, the Headers API normalizes header names
        // to lowercase, so comparing key.toLowerCase() === "set-cookie" is safe.
        const setCookieValues: string[] = [];
        const otherHeaders: Record<string, string> = {};

        for (const [key, value] of resHeaders.entries()) {
          if (key.toLowerCase() === "set-cookie") {
            setCookieValues.push(value);
          } else {
            otherHeaders[key] = value;
          }
        }
        // Set all cookies at once as an array if any exist
        if (setCookieValues.length > 0) {
          pagesRouterRes.setHeader("set-cookie", setCookieValues);
        }

        // Set non-cookie headers normally
        for (const [key, value] of Object.entries(otherHeaders)) {
          pagesRouterRes.setHeader(key, value);
        }
      }
    }
  }

  private createRequestCookies(req: PagesRouterRequest) {
    return new RequestCookies(toHeadersFromIncomingMessage(req));
  }

  /**
   * Resolves request context from any Next.js server context into a uniform shape.
   *
   * Handles the 3-way branch:
   * - Request / NextRequest: extracts headers + nextUrl from nextReq
   * - PagesRouterRequest (IncomingMessage): converts headers, constructs URL
   * - No request (Server Components / Actions): uses next/headers, url is undefined
   *
   * @returns authClient and normalizedReq for downstream use.
   *   Cookies are NOT included; only getSession needs them, and it handles
   *   cookie extraction internally to avoid eagerly calling cookies() outside
   *   request scope (which would throw in Server Components when called from
   *   methods that don't need cookies, like getAccessToken).
   * @internal
   */
  private async resolveRequestContext(
    req?: Request | PagesRouterRequest | NextRequest
  ): Promise<{
    authClient: AuthClient;
    normalizedReq?: NextRequest | PagesRouterRequest;
  }> {
    if (req) {
      if (req instanceof Request) {
        const nextReq = toNextRequest(req);
        const authClient = await this.provider.forRequest(
          nextReq.headers,
          nextReq.nextUrl
        );
        return { authClient, normalizedReq: nextReq };
      }

      // Pages Router (IncomingMessage / NextApiRequest)
      const reqHeaders = toHeadersFromIncomingMessage(req);
      const url = toUrlFromPagesRouter(req);
      const authClient = await this.provider.forRequest(reqHeaders, url);
      return {
        authClient,
        normalizedReq: req as PagesRouterRequest
      };
    }

    // Server Components / Server Actions — no request object
    const reqHeaders = await getHeaders();
    const authClient = await this.provider.forRequest(reqHeaders, undefined);
    return { authClient };
  }

  /**
   * Initiates a login redirect from a Server Action or Route Handler.
   * Use when you need to programmatically trigger the login flow rather than
   * relying on the automatic redirect from `withPageAuthRequired`.
   *
   * @param options.returnTo - Where to send the user after login. Defaults to `/`.
   * @param options.authorizationParameters - Extra parameters to forward to the `/authorize` endpoint.
   *
   * @returns A `NextResponse` that redirects the user to the Auth0 login page.
   *
   * @example
   * ```ts
   * // app/actions/login.ts
   * 'use server';
   * import { redirect } from 'next/navigation';
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function loginAction() {
   *   const res = await auth0.startInteractiveLogin({ returnTo: '/dashboard' });
   *   redirect(res.headers.get('location')!);
   * }
   * ```
   *
   */
  async startInteractiveLogin(
    options: StartInteractiveLoginOptions = {}
  ): Promise<NextResponse> {
    const reqHeaders = await getHeaders();
    const authClient = await this.provider.forRequest(reqHeaders, undefined);
    return authClient.startInteractiveLogin(options);
  }

  /**
   * Authenticates a user via Client-Initiated Backchannel Authentication (CIBA) and returns
   * the token set once the user approves the request on their device.
   *
   * Initiates the backchannel flow and polls Auth0 until the user approves or the request times out.
   * Does not require the user to be present in the browser session.
   *
   * **Prerequisite:** CIBA must be enabled in the Auth0 dashboard for your application.
   *
   * @param options.loginHint - Identifies the user to authenticate.
   * @param options.scope - Space-separated scopes to request.
   * @param options.audience - The API identifier the token should be issued for.
   *
   * @returns The token set, and optionally ID token claims and authorization details.
   *
   * @throws `BackchannelAuthenticationNotSupportedError` (code `"backchannel_authentication_not_supported_error"`) if CIBA is not enabled for your application.
   * @throws `BackchannelAuthenticationError` (code `"backchannel_authentication_error"`) if Auth0 rejects the request.
   *
   * @example
   * ```ts
   * // app/api/backchannel/route.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function POST(req: Request) {
   *   const { email } = await req.json();
   *   const tokens = await auth0.getTokenByBackchannelAuth({
   *     loginHint: { format: 'iss_sub', iss: 'https://example.us.auth0.com/', sub: email },
   *     scope: 'openid profile email',
   *   });
   *   return Response.json({ accessToken: tokens.accessToken });
   * }
   * ```
   *
   */
  async getTokenByBackchannelAuth(options: BackchannelAuthenticationOptions) {
    const reqHeaders = await getHeaders();
    const authClient = await this.provider.forRequest(reqHeaders, undefined);

    const [error, response] =
      await authClient.backchannelAuthentication(options);

    if (error) {
      throw error;
    }

    return response;
  }

  /**
   * Starts the Connect Account flow, redirecting the user to Auth0 to authorize linking a
   * third-party social account (e.g. GitHub, Google) to their existing profile.
   *
   * **Prerequisite:** "Offline Access" must be enabled in Connection Permissions for the target
   * connection. The user must have an active session.
   *
   * @param options.connection - The connection name, e.g. `"github"` or `"google-oauth2"`.
   *
   * @returns A `NextResponse` that redirects the user to Auth0 to authorize the connection.
   *
   * @throws `ConnectAccountError` (code `"missing_session"`) if the user is not logged in.
   * @throws `ConnectAccountError` (code `"failed_to_initiate"`) if starting the connect flow fails. Check `err.cause` for the underlying `MyAccountApiError`.
   * @throws `ConnectAccountError` (code `"failed_to_complete"`) if completing the connect flow fails. Check `err.cause` for the underlying `MyAccountApiError`.
   *
   * @example
   * ```ts
   * // app/actions/connect-github.ts
   * 'use server';
   * import { redirect } from 'next/navigation';
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function connectGitHub() {
   *   const res = await auth0.connectAccount({ connection: 'github' });
   *   redirect(res.headers.get('location')!);
   * }
   * ```
   *
   */
  async connectAccount(options: ConnectAccountOptions): Promise<NextResponse> {
    const reqHeaders = await getHeaders();
    const authClient = await this.provider.forRequest(reqHeaders, undefined);

    const session = await this.getSession();

    if (!session) {
      throw new ConnectAccountError({
        code: ConnectAccountErrorCodes.MISSING_SESSION,
        message: "The user does not have an active session."
      });
    }

    // Build issuer URL from authClient's domain
    const issuer = `https://${authClient.domain}/`;
    const getMyAccountTokenOpts = {
      audience: `${issuer}me/`,
      scope: "create:me:connected_accounts"
    };

    const accessToken = await this.getAccessToken(getMyAccountTokenOpts);

    const [error, connectAccountResponse] = await authClient.connectAccount({
      ...options,
      tokenSet: {
        accessToken: accessToken.token,
        expiresAt: accessToken.expiresAt,
        scope: getMyAccountTokenOpts.scope,
        audience: accessToken.audience
      }
    });

    if (error) {
      throw error;
    }

    return connectAccountResponse;
  }

  /**
   * Protects a page from unauthenticated access. Redirects to the login page and returns the
   * user to the original URL after a successful login.
   *
   * **App Router**: pass an async page function. The SDK invokes it only when a session exists.
   * Because Server Components do not know their own URL, pass `returnTo` explicitly if you need
   * the user to land back on the same page after login.
   *
   * **Pages Router**: call with no arguments (or an options object) to protect `getServerSideProps`.
   *
   * @param fn - App Router: the async page component to wrap.
   * @param opts.returnTo - Where to send the user after login. App Router default: `/`. Pages Router default: current URL.
   * @param opts.getServerSideProps - Pages Router: your own `getServerSideProps` to run after the auth check.
   *
   * @example App Router
   * ```ts
   * // app/dashboard/page.tsx
   * import { auth0 } from '@/lib/auth0';
   *
   * export default auth0.withPageAuthRequired(
   *   async function Dashboard() {
   *     const session = await auth0.getSession();
   *     return <h1>Welcome, {session!.user.name}</h1>;
   *   },
   *   { returnTo: '/dashboard' }
   * );
   * ```
   *
   * @example Pages Router
   * ```ts
   * // pages/dashboard.tsx
   * import { auth0 } from '@/lib/auth0';
   *
   * export const getServerSideProps = auth0.withPageAuthRequired();
   *
   * export default function Dashboard({ user }) {
   *   return <h1>Welcome, {user.name}</h1>;
   * }
   * ```
   *
   */
  // App Router overload - with component function
  withPageAuthRequired<
    P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts
  >(
    fn: AppRouterPageRoute<P>,
    opts?: WithPageAuthRequiredAppRouterOptions<P>
  ): AppRouterPageRoute<P>;
  // Pages Router overload - no arguments
  withPageAuthRequired(): PageRoute<{ [key: string]: any }, ParsedUrlQuery>;
  // Pages Router overload - with options
  withPageAuthRequired<
    P extends { [key: string]: any } = { [key: string]: any },
    Q extends ParsedUrlQuery = ParsedUrlQuery
  >(opts: WithPageAuthRequiredPageRouterOptions<P, Q>): PageRoute<P, Q>;
  // Implementation
  withPageAuthRequired(
    fnOrOpts?: WithPageAuthRequiredPageRouterOptions | AppRouterPageRoute,
    opts?: WithPageAuthRequiredAppRouterOptions
  ) {
    const config = {
      loginUrl: this.routes.login
    };
    const appRouteHandler = appRouteHandlerFactory(this, config);
    const pageRouteHandler = pageRouteHandlerFactory(this, config);

    if (typeof fnOrOpts === "function") {
      return appRouteHandler(fnOrOpts, opts);
    }

    return pageRouteHandler(fnOrOpts);
  }

  /**
   * Protects an API route handler. Unauthenticated requests are automatically rejected with
   * `401 Unauthorized`. Works with both App Router Route Handlers and Pages Router API routes.
   *
   * @param apiRoute - The handler function to protect.
   *
   * @example App Router
   * ```ts
   * // app/api/orders/route.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export const GET = auth0.withApiAuthRequired(async function handler(req) {
   *   const session = await auth0.getSession();
   *   return Response.json({ user: session!.user });
   * });
   * ```
   *
   * @example Pages Router
   * ```ts
   * // pages/api/orders.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export default auth0.withApiAuthRequired(async function handler(req, res) {
   *   const session = await auth0.getSession(req);
   *   res.json({ user: session!.user });
   * });
   * ```
   *
   */
  withApiAuthRequired(
    apiRoute: withApiAuthRequired.AppRouteHandlerFn | NextApiHandler
  ) {
    const pageRouteHandler = withApiAuthRequired.pageRouteHandlerFactory(this);
    const appRouteHandler = withApiAuthRequired.appRouteHandlerFactory(this);

    return (
      req: NextRequest | NextApiRequest,
      resOrParams:
        | withApiAuthRequired.AppRouteHandlerFnContext
        | NextApiResponse
    ) => {
      if (isRequest(req)) {
        return appRouteHandler(
          apiRoute as withApiAuthRequired.AppRouteHandlerFn
        )(
          req as NextRequest,
          resOrParams as withApiAuthRequired.AppRouteHandlerFnContext
        );
      }

      return (
        pageRouteHandler as withApiAuthRequired.WithApiAuthRequiredPageRoute
      )(apiRoute as NextApiHandler)(
        req as NextApiRequest,
        resOrParams as NextApiResponse
      );
    };
  }

  private async saveToSession(
    data: SessionData,
    req?: PagesRouterRequest | NextRequest,
    res?: PagesRouterResponse | NextResponse
  ) {
    if (req && res) {
      if (isRequest(req) && res instanceof NextResponse) {
        // middleware usage
        const nextReq = toNextRequest(req);
        await this.sessionStore.set(nextReq.cookies, res.cookies, data);
      } else {
        // pages router usage
        const resHeaders = new Headers();
        const resCookies = new ResponseCookies(resHeaders);
        const pagesRouterRes = res as PagesRouterResponse;

        await this.sessionStore.set(
          this.createRequestCookies(req as PagesRouterRequest),
          resCookies,
          data
        );

        for (const cookie of resHeaders.getSetCookie()) {
          pagesRouterRes.appendHeader("set-cookie", cookie);
        }

        // Set any other headers (non-cookie)
        for (const [key, value] of resHeaders.entries()) {
          if (key.toLowerCase() !== "set-cookie") {
            pagesRouterRes.setHeader(key, value);
          }
        }
      }
    } else {
      // app router usage: Server Components, Server Actions, Route Handlers
      try {
        await this.sessionStore.set(await cookies(), await cookies(), data);
      } catch (e) {
        if (process.env.NODE_ENV === "development") {
          console.warn(
            "Failed to persist the updated token set. `getAccessToken()` was likely called from a Server Component which cannot set cookies."
          );
        }
      }
    }
  }

  /**
   * Validates and extracts required configuration options.
   * @param options The client options
   * @returns The validated required options
   * @throws ConfigurationError if any required option is missing
   */
  private validateAndExtractRequiredOptions(options: Auth0ClientOptions) {
    // Base required options that are always needed
    const requiredOptions = {
      domain: options.domain ?? process.env.AUTH0_DOMAIN,
      clientId: options.clientId ?? process.env.AUTH0_CLIENT_ID,
      secret: options.secret ?? process.env.AUTH0_SECRET
    };

    const envAppBaseUrl = process.env.APP_BASE_URL?.includes(",")
      ? process.env.APP_BASE_URL.split(",")
          .map((u) => u.trim())
          .filter(Boolean)
      : process.env.APP_BASE_URL;
    const appBaseUrl = options.appBaseUrl ?? envAppBaseUrl;

    // Check client authentication options - either clientSecret OR clientAssertionSigningKey must be provided
    const clientSecret =
      options.clientSecret ?? process.env.AUTH0_CLIENT_SECRET;
    const clientAssertionSigningKey =
      options.clientAssertionSigningKey ??
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_KEY;
    const hasClientAuthentication = !!(
      clientSecret || clientAssertionSigningKey
    );

    const missing = Object.entries(requiredOptions)
      .filter(([, value]) => !value)
      .map(([key]) => key);

    // Add client authentication error if neither option is provided
    if (!hasClientAuthentication) {
      missing.push("clientAuthentication");
    }

    if (missing.length) {
      // Map of option keys to their exact environment variable names
      const envVarNames: Record<string, string> = {
        domain: "AUTH0_DOMAIN",
        clientId: "AUTH0_CLIENT_ID",
        secret: "AUTH0_SECRET"
      };

      // Standard intro message explaining the issue
      let errorMessage =
        "WARNING: Not all required options were provided when creating an instance of Auth0Client. Ensure to provide all missing options, either by passing it to the Auth0Client constructor, or by setting the corresponding environment variable.\n";

      // Add specific details for each missing option
      missing.forEach((key) => {
        if (key === "clientAuthentication") {
          errorMessage += `Missing: clientAuthentication: Set either AUTH0_CLIENT_SECRET env var or AUTH0_CLIENT_ASSERTION_SIGNING_KEY env var, or pass clientSecret or clientAssertionSigningKey in options\n`;
        } else if (envVarNames[key]) {
          errorMessage += `Missing: ${key}: Set ${envVarNames[key]} env var or pass ${key} in options\n`;
        } else {
          errorMessage += `Missing: ${key}\n`;
        }
      });

      console.error(errorMessage.trim());
    }

    // Prepare the result object with all validated options
    const result = {
      ...requiredOptions,
      appBaseUrl,
      clientSecret,
      clientAssertionSigningKey
    };

    // Type-safe assignment after validation
    return result as {
      domain: NonNullable<typeof result.domain>;
      clientId: NonNullable<typeof result.clientId>;
      secret: NonNullable<typeof result.secret>;
      appBaseUrl: typeof result.appBaseUrl;
      clientSecret: typeof result.clientSecret;
      clientAssertionSigningKey: typeof result.clientAssertionSigningKey;
    };
  }

  /**
   * Creates an authenticated HTTP client that automatically injects the user's access token
   * as a Bearer header on every request and handles token refresh transparently.
   *
   * @param req - Request for session context. Pass `undefined` in App Router; required in Pages Router.
   * @param options.baseUrl - Base URL for resolving relative paths, e.g. `"https://api.example.com"`.
   * @param options.useDPoP - Enable DPoP for this fetcher instance, overriding the global setting.
   * @param options.fetch - Custom fetch implementation (defaults to global `fetch`).
   *
   * @returns A `Fetcher` instance. Call `fetcher.fetchWithAuth(path, init?)` to make authenticated requests.
   *
   * @throws `AccessTokenError` (`"missing_session"`) if the user is not authenticated.
   *
   * @example
   * ```ts
   * // app/api/proxy/route.ts
   * import { auth0 } from '@/lib/auth0';
   *
   * export async function GET() {
   *   const fetcher = await auth0.createFetcher(undefined, {
   *     baseUrl: 'https://api.example.com',
   *   });
   *
   *   const res = await fetcher.fetchWithAuth('/users');
   *   return Response.json(await res.json());
   * }
   * ```
   *
   */
  public async createFetcher<TOutput extends Response = Response>(
    req: PagesRouterRequest | NextRequest | Request | undefined,
    options: {
      /** Enable DPoP for this fetcher instance (overrides global setting) */
      useDPoP?: boolean;
      /** Custom access token factory function. If not provided, uses the default from hooks */
      getAccessToken?: AccessTokenFactory;
      /** Base URL for relative requests. Must be provided if using relative URLs */
      baseUrl?: string;
      /** Custom fetch implementation. Falls back to global fetch if not provided */
      fetch?: CustomFetchImpl<TOutput>;
    }
  ) {
    const { authClient, normalizedReq } = await this.resolveRequestContext(req);

    const session: SessionData | null = normalizedReq
      ? await this.getSession(normalizedReq)
      : await this.getSession();

    if (!session) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      );
    }

    const getAccessToken = async (
      getAccessTokenOptions: GetAccessTokenOptions
    ) => {
      const [error, getTokenSetResponse] = await authClient.getTokenSet(
        session,
        getAccessTokenOptions || {}
      );
      if (error) {
        throw error;
      }
      return getTokenSetResponse.tokenSet;
    };

    const fetcher: Fetcher<TOutput> = await authClient.fetcherFactory({
      ...options,
      getAccessToken
    });

    return fetcher;
  }

  /**
   * Resolve mfaContextTtl with validation and fallback to default.
   * Issues console warning for invalid values instead of throwing.
   */
  private resolveMfaTokenTtl(
    optionValue: number | undefined,
    envValue: string | undefined
  ): number {
    const DEFAULT_TTL = DEFAULT_MFA_CONTEXT_TTL_SECONDS;

    // Try option value first
    if (optionValue !== undefined) {
      if (Number.isFinite(optionValue) && optionValue > 0) {
        return optionValue;
      }
      console.warn(
        `[auth0-nextjs] Invalid mfaTokenTtl option value: ${optionValue}. ` +
          `Using default: ${DEFAULT_TTL} seconds.`
      );
      return DEFAULT_TTL;
    }

    // Try environment variable
    if (envValue !== undefined) {
      const parsed = parseInt(envValue, 10);
      if (Number.isFinite(parsed) && parsed > 0) {
        return parsed;
      }
      console.warn(
        `[auth0-nextjs] Invalid AUTH0_MFA_TOKEN_TTL environment variable: ${envValue}. ` +
          `Using default: ${DEFAULT_TTL} seconds.`
      );
      return DEFAULT_TTL;
    }

    return DEFAULT_TTL;
  }
}
