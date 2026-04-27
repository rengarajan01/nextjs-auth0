import { AuthorizationParameters } from "./authorize.js";
import { TokenSet } from "./index.js";

/**
 * Options for `connectAccount()`.
 *
 * @group Server
 * @title Connect Account Options
 * @order 56
 */
export interface ConnectAccountOptions {
  /**
   * The name of the connection to link the account with (e.g., 'google-oauth2', 'facebook').
   */
  connection: string;
  /**
   * Array of scopes to request from the Identity Provider during the connect account flow.
   */
  scopes?: string[];
  /**
   * Authorization parameters to be passed to the authorization server.
   */
  authorizationParams?: AuthorizationParameters;
  /**
   * The URL to redirect to after successfully connecting the account.
   */
  returnTo?: string;
}

/** @ignore */
export enum RESPONSE_TYPES {
  CODE = "code",
  CONNECT_CODE = "connect_code"
}

/** @ignore */
export interface ConnectAccountRequest {
  tokenSet: TokenSet;
  connection: string;
  redirectUri: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  scopes?: string[];
  authorizationParams?: AuthorizationParameters;
}

/** @ignore */
export interface ConnectAccountResponse {
  connectUri: string;
  connectParams: {
    ticket: string;
  };
  authSession: string;
  expiresIn: number;
}

/** @ignore */
export interface CompleteConnectAccountRequest {
  tokenSet: TokenSet;
  authSession: string;
  connectCode: string;
  redirectUri: string;
  codeVerifier?: string;
}

/** @ignore */
export interface CompleteConnectAccountResponse {
  id: string;
  connection: string;
  accessType: string;
  scopes: string[];
  createdAt: string;
  expiresAt?: string;
}
