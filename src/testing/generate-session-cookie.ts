import { encrypt } from "../server/cookies.js";
import { SessionData } from "../types/index.js";

/** @ignore */
export type GenerateSessionCookieConfig = {
  /**
   * The secret used to derive an encryption key for the session cookie.
   *
   * **IMPORTANT**: you must use the same value as in the SDK configuration.
   */
  secret: string;
};

/**
 * Creates an encrypted session cookie that simulates a logged-in user in tests,
 * bypassing the real Auth0 login flow entirely.
 *
 * Set the returned string as the `appSession` cookie on your test HTTP requests
 * to make the SDK treat the request as authenticated.
 *
 * **Prerequisite:** `config.secret` must match the `AUTH0_SECRET` in your SDK
 * configuration, otherwise the SDK will reject the cookie as invalid.
 *
 * @param session - Session data to encode. `user` is required; `internal` is auto-populated.
 * @param session.user - The user profile to embed in the session.
 * @param session.tokenSet - Token details. Provide at least `accessToken` and `expiresAt`.
 * @param config.secret - Must match the `AUTH0_SECRET` used by `Auth0Client`.
 *
 * @returns The encrypted cookie string. Expires 1 hour from the time of generation.
 *
 * @example
 * ```ts
 * import { generateSessionCookie } from '@auth0/nextjs-auth0/testing';
 *
 * const cookie = await generateSessionCookie(
 *   {
 *     user: {
 *       sub:            'auth0|64b2e5f8a3c1d90012ef4567',
 *       name:           'Jane Doe',
 *       email:          'jane@example.com',
 *       email_verified: true
 *     },
 *     tokenSet: {
 *       accessToken: 'test-access-token',
 *       expiresAt:   Math.floor(Date.now() / 1000) + 3600
 *     }
 *   },
 *   { secret: process.env.AUTH0_SECRET! }
 * );
 * // "Fe26.2**abc123..." (encrypted cookie string)
 *
 * // Pass it in your test request to simulate an authenticated user:
 * const res = await fetch('/api/protected', {
 *   headers: { Cookie: `appSession=${cookie}` },
 * });
 * ```
 *
 * @group Testing
 * @title Generate Session Cookie
 * @order 1
 */
export const generateSessionCookie = async (
  session: Partial<SessionData>,
  config: GenerateSessionCookieConfig
): Promise<string> => {
  if (!("internal" in session)) {
    session.internal = {
      sid: "auth0-sid",
      createdAt: Math.floor(Date.now() / 1000)
    };
  }

  const maxAge = 60 * 60; // 1 hour in seconds
  const expiration = Math.floor(Date.now() / 1000 + maxAge);

  return encrypt(session, config.secret, expiration);
};
