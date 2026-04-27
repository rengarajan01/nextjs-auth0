"use client";

import useSWR from "swr";

import type { User } from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";


/**
 * Returns the logged-in user's profile inside a React component.
 *
 * **Prerequisite:** {@link Auth0Provider} must wrap the component tree.
 *
 * @returns `{ user, isLoading, error, invalidate }`. `user` is `null` when logged out
 * and `undefined` while loading. Call `invalidate()` to force a fresh profile fetch.
 *
 * Sample `user` object:
 * ```json
 * {
 *   "sub": "auth0|64b2e5f8a3c1d90012ef4567",
 *   "name": "Jane Doe",
 *   "nickname": "jane",
 *   "given_name": "Jane",
 *   "family_name": "Doe",
 *   "picture": "https://cdn.auth0.com/avatars/jd.png",
 *   "email": "jane@example.com",
 *   "email_verified": true,
 *   "org_id": "org_abc123"
 * }
 * ```
 *
 * @example
 * ```tsx
 * // components/profile.tsx
 * import { useUser } from '@auth0/nextjs-auth0/client';
 *
 * export default function Profile() {
 *   const { user, isLoading, error } = useUser();
 *
 *   if (isLoading) return <p>Loading...</p>;
 *   if (error)     return <p>Error: {error.message}</p>;
 *   if (!user)     return <a href="/auth/login">Log in</a>;
 *
 *   return <p>Welcome, {user.name}</p>;
 *   //                      ^ "Jane Doe"
 * }
 * ```
 *
 * @group Client
 * @title Get User
 * @order 2
 */


export function useUser(): {
  user: User | null | undefined;
  isLoading: boolean;
  error: Error | null | undefined;
  invalidate: () => void;
} {
  const { data, error, isLoading, mutate } = useSWR<User, Error, string>(
    normalizeWithBasePath(
      process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile"
    ),
    (...args) =>
      fetch(...args).then((res) => {
        if (!res.ok) {
          throw new Error("Unauthorized");
        }

        if (res.status === 204) {
          return null;
        }

        return res.json();
      })
  );

  if (error) {
    return {
      user: null,
      isLoading: false,
      error,
      invalidate: () => mutate()
    };
  }

  if (data) {
    return {
      user: data,
      isLoading: false,
      error: null,
      invalidate: () => mutate()
    };
  }

  return {
    user: data,
    isLoading,
    error,
    invalidate: () => mutate()
  };
}
