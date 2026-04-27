"use client";

import React from "react";
import { SWRConfig } from "swr";

import { User } from "../../types/index.js";

/**
 * Bridges your server-side session to client components. Wrap your root layout with this
 * provider and pass the session user; {@link useUser} will return that user immediately
 * on first render with no loading state and no network request.
 *
 * Without this provider, {@link useUser} still works but always starts as `isLoading: true`
 * while it fetches `/auth/profile`, causing a flash of unauthenticated state on every page load.
 * SWR revalidates the session in the background (on tab focus, reconnect) regardless.
 *
 * **Prerequisite:** Call `auth0.getSession()` in your server layout and pass `session?.user` here.
 *
 * @param props.user - User from the server session. Pass `undefined` when no session exists.
 * @param props.children - Your application's component tree.
 *
 * @example
 * ```tsx
 * // app/layout.tsx
 * import { Auth0Provider } from '@auth0/nextjs-auth0/client';
 * import { auth0 } from '@/lib/auth0';
 *
 * export default async function RootLayout({ children }: { children: React.ReactNode }) {
 *   const session = await auth0.getSession();
 *   // session?.user:
 *   // {
 *   //   "sub": "auth0|64b2e5f8a3c1d90012ef4567",
 *   //   "name": "Jane Doe",
 *   //   "email": "jane@example.com",
 *   //   "picture": "https://cdn.auth0.com/avatars/jd.png",
 *   //   "email_verified": true
 *   // }
 *
 *   return (
 *     <html>
 *       <body>
 *         <Auth0Provider user={session?.user}>
 *           {children}
 *         </Auth0Provider>
 *       </body>
 *     </html>
 *   );
 * }
 * ```
 *
 * @group Client
 * @title Initialize Provider
 * @order 1
 */
export function Auth0Provider({
  user,
  children
}: {
  user?: User;
  children: React.ReactNode;
}) {
  return (
    <SWRConfig
      value={{
        fallback: {
          [process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile"]: user
        }
      }}
    >
      {children}
    </SWRConfig>
  );
}
