import type { ParsedUrlQuery } from "querystring";
import {
  GetServerSideProps,
  GetServerSidePropsContext,
  GetServerSidePropsResult
} from "next";

import { User } from "../../types/index.js";
import { Auth0Client } from "../client.js";

/** @ignore */
export type GetServerSidePropsResultWithSession<P = any> =
  GetServerSidePropsResult<P & { user: User }>;

/** @ignore */
export type PageRoute<P, Q extends ParsedUrlQuery = ParsedUrlQuery> = (
  ctx: GetServerSidePropsContext<Q>
) => Promise<GetServerSidePropsResultWithSession<P>>;

/** @ignore */
export type AppRouterPageRouteOpts = {
  params?: Promise<Record<string, string | string[]>>;
  searchParams?: Promise<{ [key: string]: string | string[] | undefined }>;
};

/** @ignore */
export type AppRouterPageRoute<
  P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts
> = (obj: P) => Promise<any>;

/** @ignore */
export type WithPageAuthRequiredPageRouterOptions<
  P extends { [key: string]: any } = { [key: string]: any },
  Q extends ParsedUrlQuery = ParsedUrlQuery
> = {
  getServerSideProps?: GetServerSideProps<P, Q>;
  returnTo?: string;
};

/** @ignore */
export type WithPageAuthRequiredPageRouter = <
  P extends { [key: string]: any } = { [key: string]: any },
  Q extends ParsedUrlQuery = ParsedUrlQuery
>(
  opts?: WithPageAuthRequiredPageRouterOptions<P, Q>
) => PageRoute<P, Q>;

/** @ignore */
export type WithPageAuthRequiredAppRouterOptions<
  P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts
> = {
  /**
   * The URL to redirect the user to after a successful login.
   * * Can be a static string or a function that receives the page props.
   * When used as a function, the generic `P` ensures that `params` and `searchParams`
   * match the specific types of your route (e.g., from Next.js `PageProps`).
   */
  returnTo?: string | ((obj: P) => Promise<string> | string);
};

/** @ignore */
export type WithPageAuthRequiredAppRouter = <
  P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts
>(
  fn: AppRouterPageRoute<P>,
  opts?: WithPageAuthRequiredAppRouterOptions<P>
) => AppRouterPageRoute<P>;

/** @ignore */
export type WithPageAuthRequired = WithPageAuthRequiredPageRouter &
  WithPageAuthRequiredAppRouter;

export const appRouteHandlerFactory =
  (
    client: Auth0Client,
    config: {
      loginUrl: string;
    }
  ): WithPageAuthRequiredAppRouter =>
  <P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts>(
    handler: AppRouterPageRoute<P>,
    opts: WithPageAuthRequiredAppRouterOptions<P> = {}
  ) =>
  async (params: P) => {
    const session = await client.getSession();

    if (!session?.user) {
      const returnTo =
        typeof opts.returnTo === "function"
          ? await opts.returnTo(params)
          : opts.returnTo;
      const { redirect } = await import("next/navigation.js");
      redirect(
        `${config.loginUrl}${returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : ""}`
      );
    }
    return handler(params);
  };

export const pageRouteHandlerFactory =
  (
    client: Auth0Client,
    config: {
      loginUrl: string;
    }
  ): WithPageAuthRequiredPageRouter =>
  ({ getServerSideProps, returnTo } = {}) =>
  async (ctx) => {
    const session = await client.getSession(ctx.req);

    if (!session?.user) {
      return {
        redirect: {
          destination: `${config.loginUrl}?returnTo=${encodeURIComponent(returnTo || ctx.resolvedUrl)}`,
          permanent: false
        }
      };
    }
    let ret: any = { props: {} };
    if (getServerSideProps) {
      ret = await getServerSideProps(ctx);
    }
    if (ret.props instanceof Promise) {
      const props = await ret.props;
      return {
        ...ret,
        props: {
          user: session.user,
          ...props
        }
      };
    }
    return { ...ret, props: { user: session.user, ...ret.props } };
  };
