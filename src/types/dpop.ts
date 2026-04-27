/**
 * ES256 key pair for DPoP (Demonstrating Proof-of-Possession).
 * Generate with `generateDpopKeyPair()` and pass to `Auth0Client` via `dpopKeyPair`.
 *
 * @group Server
 * @title DPoP Key Pair
 * @order 150
 */
export interface DpopKeyPair {
  /** ES256 private key used to sign DPoP proofs */
  privateKey: CryptoKey;
  /** ES256 public key included in DPoP proofs for verification */
  publicKey: CryptoKey;
}

/**
 * DPoP timing validation options. Pass to `Auth0Client` via `dpopOptions`.
 *
 * @example
 * ```ts
 * export const auth0 = new Auth0Client({
 *   useDPoP: true,
 *   dpopOptions: {
 *     clockTolerance: 60,
 *     retry: { delay: 200, jitter: true },
 *   },
 * });
 * ```
 *
 * @group Server
 * @title DPoP Options
 * @order 151
 */
export interface DpopOptions {
  /**
   * Clock skew adjustment in seconds. Positive values shift the assumed current time forward;
   * negative values shift it backward. Default: `0`.
   */
  clockSkew?: number;

  /**
   * Clock tolerance in seconds for DPoP proof DateTime claims validation.
   * Higher values are more permissive but may weaken replay protection. Default: `30`.
   */
  clockTolerance?: number;

  /**
   * Configuration for DPoP nonce error retry behavior.
   */
  retry?: RetryConfig;
}

/**
 * Retry configuration for DPoP nonce errors. Pass to `DpopOptions.retry`.
 *
 * @group Server
 * @title Retry Config
 * @order 152
 */
export interface RetryConfig {
  /**
   * Delay in milliseconds before retrying on DPoP nonce error. Default: `100`.
   */
  delay?: number;

  /**
   * Whether to add jitter (randomness) to the retry delay to prevent thundering herd.
   * When enabled, actual delay is 50-100% of `delay`. Default: `true`.
   */
  jitter?: boolean;
}
