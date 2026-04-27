/**
 * MCD (Multiple Custom Domains) types and interfaces.
 *
 * Public exports: {@link DomainResolver}, {@link DiscoveryCacheOptions}.
 * Internal: {@link MCDMetadata}, {@link SessionCheckResult}.
 */

import type { SdkError } from "../errors/sdk-error.js";
import type { SessionData } from "./index.js";

/**
 * A function that resolves the Auth0 domain from the incoming request context.
 * Use this instead of a static domain string when serving multiple Auth0 tenants or custom
 * domains from a single Next.js app (Multiple Custom Domains).
 *
 * Receives `headers` (always present) and `url` (available in middleware and Pages Router,
 * `undefined` in Server Components). Throw on failure; the SDK wraps it in `DomainResolutionError`.
 *
 * @example Header-based routing (B2C multi-brand)
 * ```ts
 * // lib/auth0.ts
 * export const auth0 = new Auth0Client({
 *   domain: ({ headers }) => {
 *     const host = headers.get('host') ?? '';
 *     if (host.startsWith('brand1.')) return 'auth.brand1.com';
 *     if (host.startsWith('brand2.')) return 'auth.brand2.com';
 *     return 'auth.default.com';
 *   },
 * });
 * ```
 *
 * @example Database lookup (B2B SaaS per-tenant)
 * ```ts
 * export const auth0 = new Auth0Client({
 *   domain: async ({ headers }) => {
 *     const tenantId = headers.get('x-tenant-id');
 *     const domain = await db.getAuth0Domain(tenantId);
 *     if (!domain) throw new Error(`Unknown tenant: ${tenantId}`);
 *     return domain;
 *   },
 * });
 * ```
 *
 * @group Server
 * @title Domain Resolver
 * @order 25
 */
export type DomainResolver = (config: {
  headers: Headers;
  url?: URL;
}) => Promise<string> | string;

/**
 * Controls the OIDC discovery metadata cache used in Multiple Custom Domains mode.
 *
 * - `ttl`: how long to cache discovery metadata for each domain, in seconds. Default: `600` (10 min).
 * - `maxEntries`: max number of domains to cache concurrently. Default: `100`. Evicts least-recently-used entries.
 *
 * Pass to `Auth0Client` via the `discoveryCache` option.
 *
 * @group Server
 * @title Discovery Cache Options
 * @order 26
 */
export interface DiscoveryCacheOptions {
  ttl?: number;
  maxEntries?: number;
}

/** @ignore */
export interface MCDMetadata {
  domain: string;
  issuer: string;
}

/** @ignore */
export interface SessionCheckResult {
  error: SdkError | null;
  session: SessionData | null;
  exists: boolean;
}
