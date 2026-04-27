"use client";

import React, { ComponentType, JSX, useEffect } from "react";
import { useRouter as usePagesRouter } from "next/compat/router.js";
import { usePathname } from "next/navigation.js";

import type { User } from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";
import { useUser } from "../hooks/use-user.js";

const defaultOnRedirecting = (): JSX.Element => <></>;
const defaultOnError = (): JSX.Element => <></>;

/** @ignore */
export interface WithPageAuthRequiredOptions {
  returnTo?: string;
  onRedirecting?: () => JSX.Element;
  onError?: (error: Error) => JSX.Element;
}

export interface UserProps {
  user: User;
}

/** @ignore */
export type WithPageAuthRequired = <P extends object>(
  Component: ComponentType<P & UserProps>,
  options?: WithPageAuthRequiredOptions
) => React.FC<P>;

/**
 * Protects a React page. Unauthenticated users are automatically redirected to login
 * and returned to the same page afterwards. The wrapped component always receives a
 * `user` prop containing the logged-in user's profile.
 *
 * **Prerequisite:** Auth0 login route (`/auth/login`) must be configured.
 *
 * @param Component - The React page component to protect. Receives `user` as an extra prop.
 * @param options.returnTo - Where to send the user after login. Default: current URL.
 * @param options.onRedirecting - What to render while the redirect is in progress. Default: empty fragment.
 * @param options.onError - What to render if the profile fetch fails. Receives the `Error`. Default: empty fragment.
 *
 * @returns A `React.FC` that enforces authentication before rendering `Component`.
 *
 * **`user` prop:**
 * ```json
 * {
 *   "sub": "auth0|64b2e5f8a3c1d90012ef4567",
 *   "name": "Jane Doe",
 *   "email": "jane@example.com",
 *   "picture": "https://cdn.auth0.com/avatars/jd.png",
 *   "email_verified": true,
 *   "org_id": "org_abc123"
 * }
 * ```
 *
 * @example
 * ```tsx
 * // pages/dashboard.tsx
 * import { withPageAuthRequired } from '@auth0/nextjs-auth0/client';
 *
 * function Dashboard({ user }) {
 *   // Unauthenticated users never reach here; they are redirected to /auth/login first.
 *   return <h1>Welcome, {user.name}</h1>;
 *   //                        ^ "Jane Doe"
 * }
 *
 * export default withPageAuthRequired(Dashboard, {
 *   returnTo:       '/dashboard',
 *   onRedirecting:  () => <p>Redirecting to login...</p>,
 *   onError:        (error) => <p>Error: {error.message}</p>,
 * });
 * ```
 *
 * @group Client
 * @title Protect a Page
 * @order 4
 */
export const withPageAuthRequired: WithPageAuthRequired = (
  Component,
  options = {}
) => {
  return function WithPageAuthRequired(props): JSX.Element {
    const {
      returnTo,
      onRedirecting = defaultOnRedirecting,
      onError = defaultOnError
    } = options;
    const loginUrl = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_LOGIN_ROUTE || "/auth/login"
    );
    const { user, error, isLoading } = useUser();
    const pagesRouter = usePagesRouter();
    const pathname = usePathname();

    useEffect(() => {
      if (pagesRouter && !pagesRouter.isReady) return;
      if ((user && !error) || isLoading) return;

      let returnToPath: string;

      if (!returnTo) {
        const currentLocation = window.location;
        returnToPath = pathname + currentLocation.search + currentLocation.hash;
      } else {
        returnToPath = returnTo;
      }

      window.location.assign(
        `${loginUrl}?returnTo=${encodeURIComponent(returnToPath)}`
      );
    }, [user, error, isLoading]);

    if (error) return onError(error);
    if (user) {
      const componentProps = {
        ...props,
        user
      } as React.ComponentProps<typeof Component> & UserProps;
      return <Component {...componentProps} />;
    }

    return onRedirecting();
  };
};
