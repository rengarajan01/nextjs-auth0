import { AccessTokenError } from "../../errors/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

/**
 * Configuration options for fetching an access token.
 */
export type AccessTokenOptions = {
  /** * The specific permissions you are requesting from the user. 
   * @example "read:users write:orders"
   */
  scope?: string;

  /** * The specific API you want to communicate with. 
   * @example "https://api.stripe.com/v1"
   */
  audience?: string;

  /** * If true, returns the full token object (with expiration details) 
   * instead of just the raw token string. 
   * @default false
   */
  includeFullResponse?: boolean;
};

/**
 * The complete data payload returned by the authentication server.
 */
export type AccessTokenResponse = {
  /** The actual JWT (JSON Web Token) string used for authorization. */
  token: string;
  /** The permissions granted by this token. */
  scope?: string;
  /** The exact timestamp (in seconds) when this token becomes invalid. */
  expires_at?: number;
  /** The number of seconds until this token expires. */
  expires_in?: number;
  /** The type of token returned (usually "Bearer"). */
  token_type?: string;
};

export async function getAccessToken(
  options: AccessTokenOptions & { includeFullResponse: true }
): Promise<AccessTokenResponse>;
/**
 * Fetches a JWT access token for the logged-in user to authorize browser-to-API calls.
 * Automatically refreshes the token if it has expired.
 *
 * **Prerequisite:** User must be logged in. Call from a Client Component only.
 *
 * @param options.scope - Permissions to request, space-separated. Must be a subset of the scopes granted at login. Example: `"read:orders write:orders"`
 * @param options.audience - API identifier the token is issued for. Required when calling multiple APIs. Example: `"https://api.myapp.com"`
 * @param options.includeFullResponse - Set `true` to return the full token object instead of just the JWT string. Default: `false`.
 *
 * @returns
 * Default (`includeFullResponse` omitted or `false`): the raw JWT string:
 * ```
 * "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHw2NE..."
 * ```
 * When `includeFullResponse: true`:
 * ```json
 * {
 *   "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHw2NE...",
 *   "scope": "openid profile email read:orders",
 *   "expires_at": 1716239022,
 *   "expires_in": 86400,
 *   "token_type": "Bearer"
 * }
 * ```
 *
 * @throws `AccessTokenError`. Check `error.code` to handle the cause:
 * - `"missing_session"`: no active session, user must log in
 * - `"missing_refresh_token"`: session has no refresh token, user must log in again
 * - `"failed_to_refresh_token"`: Auth0 rejected the refresh, token expired or revoked
 *
 * @example
 * ```ts
 * // components/orders.tsx: fetch protected data from the browser
 * import { getAccessToken } from '@auth0/nextjs-auth0/client';
 *
 * export default function Orders() {
 *   async function loadOrders() {
 *     const token = await getAccessToken();
 *     // "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
 *
 *     const res  = await fetch('https://api.myapp.com/orders', {
 *       headers: { Authorization: `Bearer ${token}` },
 *     });
 *     const data = await res.json();
 *     // { "orders": [ { "id": 1, "item": "Widget" }, ... ] }
 *   }
 * }
 * ```
 *
 * @example
 * ```ts
 * // With full response: inspect expiry or token type before the request.
 * const tokenData = await getAccessToken({ includeFullResponse: true });
 * // {
 * //   "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
 * //   "scope": "openid profile email",
 * //   "expires_at": 1716239022,
 * //   "expires_in": 86400,
 * //   "token_type": "Bearer"
 * // }
 *
 * await fetch('https://api.myapp.com/orders', {
 *   headers: { Authorization: `${tokenData.token_type} ${tokenData.token}` },
 * });
 * ```
 *
 * @group Client
 * @title Get Access Token
 * @order 3
 */
export async function getAccessToken(
  options?: AccessTokenOptions & { includeFullResponse?: false }
): Promise<string>;
export async function getAccessToken(
  options: AccessTokenOptions = {}
): Promise<string | AccessTokenResponse> {
  const urlParams = new URLSearchParams();

  // We only want to add the audience if it's explicitly provided
  if (options.audience) {
    urlParams.append("audience", options.audience);
  }

  // We only want to add the scope if it's explicitly provided
  if (options.scope) {
    urlParams.append("scope", options.scope);
  }

  let url = normalizeWithBasePath(
    process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token"
  );

  // Only append the query string if we have any url parameters to add
  if (urlParams.size > 0) {
    url = url + `?${urlParams.toString()}`;
  }

  const tokenRes = await fetch(url);

  if (!tokenRes.ok) {
    // try to parse it as JSON and throw the error from the API
    // otherwise, throw a generic error
    let accessTokenError;
    try {
      accessTokenError = await tokenRes.json();
    } catch (e) {
      throw new Error(
        "An unexpected error occurred while trying to fetch the access token."
      );
    }

    throw new AccessTokenError(
      accessTokenError.error.code,
      accessTokenError.error.message
    );
  }

  const tokenSet: AccessTokenResponse = await tokenRes.json();
  return options.includeFullResponse ? tokenSet : tokenSet.token;
}