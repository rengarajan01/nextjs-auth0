import type { SessionData, SessionDataStore } from "../../types/index.js";
import {
  CookieOptions,
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies
} from "../cookies.js";

/**
 * Cookie configuration for the session cookie. Pass to `Auth0Client` via the `session.cookie` option.
 *
 * @group Server
 * @title Session Cookie Options
 * @order 130
 */
export interface SessionCookieOptions {
  /**
   * The name of the session cookie.
   *
   * Default: `__session`.
   */
  name?: string;
  /**
   * The sameSite attribute of the session cookie.
   *
   * Default: `lax`.
   */
  sameSite?: "strict" | "lax" | "none";
  /**
   * The secure attribute of the session cookie.
   *
   * Default: depends on the protocol of the application's base URL. If the protocol is `https`, then `true`, otherwise `false`.
   */
  secure?: boolean;
  /**
   * The path attribute of the session cookie. Will be set to '/' by default.
   */
  path?: string;
  /**
   * Specifies the value for the {@link https://tools.ietf.org/html/rfc6265#section-5.2.3|Domain Set-Cookie attribute}. By default, no
   * domain is set, and most clients will consider the cookie to apply to only
   * the current domain.
   */
  domain?: string;
  /**
   * The transient attribute of the session cookie. When true, the cookie will not persist beyond the current session.
   */
  transient?: boolean;
}

/**
 * Session lifetime configuration. Pass to `Auth0Client` via the `session` option.
 *
 * @group Server
 * @title Session Configuration
 * @order 131
 */
export interface SessionConfiguration {
  /**
   * A boolean indicating whether rolling sessions should be used or not.
   *
   * When enabled, the session will continue to be extended as long as it is used within the inactivity duration.
   * Once the upper bound, set via the `absoluteDuration`, has been reached, the session will no longer be extended.
   *
   * Default: `true`.
   */
  rolling?: boolean;
  /**
   * The absolute duration after which the session will expire. The value must be specified in seconds.
   *
   * Once the absolute duration has been reached, the session will no longer be extended.
   *
   * Default: 3 days.
   */
  absoluteDuration?: number;
  /**
   * The duration of inactivity after which the session will expire. The value must be specified in seconds.
   *
   * The session will be extended as long as it was active before the inactivity duration has been reached.
   *
   * Default: 1 day.
   */
  inactivityDuration?: number;

  /**
   * The options for the session cookie.
   */
  cookie?: SessionCookieOptions;
}

/**
 * Options passed to `AbstractSessionStore` subclass constructor.
 * Extends `SessionConfiguration` with the required `secret` and optional custom `store`.
 *
 * @group Server
 * @title Session Store Options
 * @order 132
 */
export interface SessionStoreOptions extends SessionConfiguration {
  secret: string;
  store?: SessionDataStore;

  cookieOptions?: SessionCookieOptions;
}

const SESSION_COOKIE_NAME = "__session";

/**
 * Base class for custom session storage. Extend this when you need to persist sessions
 * to a database, Redis, or any external store instead of the default encrypted cookie.
 *
 * Implement three abstract methods: `get`, `set`, and `delete`. Pass your subclass to
 * `Auth0Client` via the `sessionStore` option.
 *
 * @example
 * ```ts
 * // lib/redis-session-store.ts
 * import { AbstractSessionStore } from '@auth0/nextjs-auth0/server';
 * import type { RequestCookies, ResponseCookies } from '@auth0/nextjs-auth0/server';
 * import { redis } from '@/lib/redis';
 *
 * export class RedisSessionStore extends AbstractSessionStore {
 *   async get(reqCookies) {
 *     const sid = reqCookies.get(this.sessionCookieName)?.value;
 *     if (!sid) return null;
 *     const raw = await redis.get(sid);
 *     return raw ? JSON.parse(raw) : null;
 *   }
 *
 *   async set(reqCookies, resCookies, session) {
 *     const sid = reqCookies.get(this.sessionCookieName)?.value ?? crypto.randomUUID();
 *     await redis.setex(sid, this.calculateMaxAge(session.internal.createdAt), JSON.stringify(session));
 *     resCookies.set(this.sessionCookieName, sid, this.cookieConfig);
 *   }
 *
 *   async delete(reqCookies, resCookies) {
 *     const sid = reqCookies.get(this.sessionCookieName)?.value;
 *     if (sid) await redis.del(sid);
 *     resCookies.delete(this.sessionCookieName);
 *   }
 * }
 *
 * // lib/auth0.ts
 * export const auth0 = new Auth0Client({ sessionStore: new RedisSessionStore({ secret: '...' }) });
 * ```
 *
 * @group Server
 * @title Abstract Session Store
 * @order 15
 */
export abstract class AbstractSessionStore {
  public secret: string;
  public sessionCookieName: string;

  protected rolling: boolean;
  private absoluteDuration: number;
  private inactivityDuration: number;

  public store?: SessionDataStore;

  public cookieConfig: CookieOptions;

  constructor({
    secret,

    rolling = true,
    absoluteDuration = 60 * 60 * 24 * 3, // 3 days in seconds
    inactivityDuration = 60 * 60 * 24 * 1, // 1 day in seconds
    store,

    cookieOptions
  }: SessionStoreOptions) {
    this.secret = secret;

    this.rolling = rolling;
    this.absoluteDuration = absoluteDuration;
    this.inactivityDuration = inactivityDuration;
    this.store = store;

    this.sessionCookieName = cookieOptions?.name ?? SESSION_COOKIE_NAME;
    this.cookieConfig = {
      httpOnly: true,
      sameSite: cookieOptions?.sameSite ?? "lax",
      secure: cookieOptions?.secure ?? false,
      path: cookieOptions?.path ?? "/",
      domain: cookieOptions?.domain,
      transient: cookieOptions?.transient
    };
  }

  abstract get(
    reqCookies: RequestCookies | ReadonlyRequestCookies
  ): Promise<SessionData | null>;

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header. If the `iat` property
   * is present on the session, then it will be used to compute the `maxAge` cookie value.
   */
  abstract set(
    reqCookies: RequestCookies | ReadonlyRequestCookies,
    resCookies: ResponseCookies,
    session: SessionData,
    isNew?: boolean
  ): Promise<void>;

  abstract delete(
    reqCookies: RequestCookies | ReadonlyRequestCookies,
    resCookies: ResponseCookies
  ): Promise<void>;

  /**
   * isRolling returns true if rolling sessions are enabled.
   */
  get isRolling(): boolean {
    return this.rolling;
  }

  /**
   * epoch returns the time since unix epoch in seconds.
   */
  epoch() {
    return (Date.now() / 1000) | 0;
  }

  /**
   * calculateMaxAge calculates the max age of the session based on createdAt and the rolling and absolute durations.
   */
  calculateMaxAge(createdAt: number) {
    if (!this.rolling) {
      return this.absoluteDuration;
    }

    const updatedAt = this.epoch();
    const expiresAt = Math.min(
      updatedAt + this.inactivityDuration,
      createdAt + this.absoluteDuration
    );
    // Fix race condition: use the same updatedAt timestamp for consistency
    const maxAge = expiresAt - updatedAt;

    return maxAge > 0 ? maxAge : 0;
  }
}
