import type { User } from "../types/index.js";

/**
 * The default set of OIDC claims stored in the session user object.
 *
 * @group Server
 * @title Default ID Token Claims
 * @order 140
 */
export const DEFAULT_ID_TOKEN_CLAIMS = [
  "sub",
  "name",
  "nickname",
  "given_name",
  "family_name",
  "picture",
  "email",
  "email_verified",
  "org_id"
];

/**
 * Filters a claims object to keep only the standard OIDC claims listed in `DEFAULT_ID_TOKEN_CLAIMS`.
 * All other claims are stripped.
 *
 * Useful inside a `beforeSessionSaved` hook when the ID token includes custom claims you do not
 * want to store in the session.
 *
 * @param claims - The raw claims object, typically `session.user` from the `beforeSessionSaved` callback.
 *
 * @returns A `User` object containing only the default claims.
 *
 * @example
 * ```ts
 * // lib/auth0.ts
 * import { Auth0Client, filterDefaultIdTokenClaims } from '@auth0/nextjs-auth0/server';
 *
 * export const auth0 = new Auth0Client({
 *   async beforeSessionSaved(session) {
 *     return {
 *       ...session,
 *       user: {
 *         ...filterDefaultIdTokenClaims(session.user),
 *         // add back only the custom claims you want to keep
 *         role: session.user.role,
 *       },
 *     };
 *   },
 * });
 * ```
 *
 * @group Server
 * @title Filter Default ID Token Claims
 * @order 141
 */
export function filterDefaultIdTokenClaims(claims: { [key: string]: any }) {
  return Object.keys(claims).reduce((acc, key) => {
    if (DEFAULT_ID_TOKEN_CLAIMS.includes(key)) {
      acc[key] = claims[key];
    }
    return acc;
  }, {} as User);
}
