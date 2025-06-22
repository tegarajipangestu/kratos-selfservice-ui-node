// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0
import {
  defaultConfig,
  requireAuth,
  RouteCreator,
  RouteRegistrator,
  logger,
} from "../pkg"
import { navigationMenu } from "../pkg/ui"
import { Identity } from "@ory/client"
import { CodeBox, Typography } from "@ory/elements-markup"

export const createSessionsRoute: RouteCreator =
  (createHelpers) => async (req, res) => {
    res.locals.projectName = "Session Information"
    const { frontend, identity } = createHelpers(req, res)
    const session = req.session

    // Create a logout URL
    const logoutUrl =
      (
        await frontend
          .createBrowserLogoutFlow({ cookie: req.header("cookie") })
          .catch(() => ({ data: { logout_url: "" } }))
      ).data.logout_url || ""

    const identityCredentialTrait =
      session?.identity?.traits.email ||
      session?.identity?.traits.username ||
      ""

    const sessionText =
      identityCredentialTrait !== ""
        ? ` and you are currently logged in as ${identityCredentialTrait} `
        : ""

    // Retrieve OIDC credentials from admin API if we have an identity
    let oidcCredentials = {
      provider: "",
      id_token: null as string | null,
      access_token: null as string | null,
      refresh_token: null as string | null,
    }

    if (session?.identity?.id) {
      try {
        // Call the admin API to get the identity with OIDC credentials
        const { data: identityDetails } = await identity.getIdentity({
          id: session.identity.id,
          includeCredential: ["oidc"],
        })

        logger.debug("Retrieved identity with credentials", {
          identityId: session.identity.id,
        })

        // Extract OIDC credentials if they exist
        if (identityDetails.credentials?.oidc?.config) {
          // Cast to appropriate type since we know the structure from the API documentation
          const oidcConfig = identityDetails.credentials.oidc.config as {
            providers?: Array<{
              provider: string
              initial_id_token?: string
              initial_access_token?: string
              initial_refresh_token?: string
            }>
          }

          if (oidcConfig.providers) {
            const googleProvider = oidcConfig.providers.find(
              (p: { provider: string }) => p.provider === "google",
            )

            if (googleProvider) {
              oidcCredentials = {
                provider: "google",
                id_token: googleProvider.initial_id_token || null,
                access_token: googleProvider.initial_access_token || null,
                refresh_token: googleProvider.initial_refresh_token || null,
              }
              console.log("oidcCredentials", oidcCredentials)
              logger.debug("Found Google OIDC provider credentials")
            }
          }
        }
      } catch (error) {
        logger.error("Error retrieving identity details", {
          error,
          identityId: session.identity.id,
        })
      }
    }

    res.render("session", {
      layout: "welcome",
      sessionInfoText: Typography({
        children: `Your browser holds an active Ory Session for ${req.header(
          "host",
        )}${sessionText}- changing properties inside Acount Settings will be reflected in the decoded Ory Session.`,
        size: "small",
        color: "foregroundMuted",
      }),
      traits: {
        id: session?.identity?.id,
        // sometimes the identity schema could contain recursive objects
        // for this use case we will just stringify the object instead of recursively flatten the object
        ...Object.entries(session?.identity?.traits).reduce<
          Record<string, any>
        >((traits, [key, value]) => {
          traits[key] =
            typeof value === "object" ? JSON.stringify(value) : value
          return traits
        }, {}),
        "signup date": session?.identity?.created_at || "",
        "authentication level":
          session?.authenticator_assurance_level === "aal2"
            ? "two-factor used (aal2)"
            : "single-factor used (aal1)",
        ...(session?.expires_at && {
          "session expires at": new Date(session?.expires_at).toUTCString(),
        }),
        ...(session?.authenticated_at && {
          "session authenticated at": new Date(
            session?.authenticated_at,
          ).toUTCString(),
        }),
      },

      // map the session's authentication level to a human readable string
      // this produces a list of objects
      authMethods: session?.authentication_methods?.reduce<any>(
        (methods, method, i) => {
          methods.push({
            [`authentication method used`]: `${method.method} (${
              method.completed_at && new Date(method.completed_at).toUTCString()
            })`,
          })
          return methods
        },
        [],
      ),
      // OIDC credentials from admin API

      oidcCredentials,
      hasOidcCredentials: Boolean(
        oidcCredentials.id_token ||
          oidcCredentials.access_token ||
          oidcCredentials.refresh_token,
      ),
      sessionCodeBox: CodeBox({
        className: "session-code-box",
        children: JSON.stringify(session, null, 2),
      }),
      // OIDC tokens code box if available
      oidcTokensCodeBox: oidcCredentials.id_token
        ? CodeBox({
            className: "oidc-tokens-code-box oidc-tokens-scrollable",
            children: JSON.stringify(
              {
                provider: oidcCredentials.provider,
                initial_id_token: oidcCredentials.id_token,
                initial_access_token: oidcCredentials.access_token,
                initial_refresh_token: oidcCredentials.refresh_token,
              },
              null,
              2,
            ),
          })
        : null,
      nav: navigationMenu({
        navTitle: res.locals.projectName,
        session,
        logoutUrl,
        selectedLink: "sessions",
      }),
    })
  }

export const registerSessionsRoute: RouteRegistrator = (
  app,
  createHelpers = defaultConfig,
  route = "/sessions",
) => {
  app.get(route, requireAuth(createHelpers), createSessionsRoute(createHelpers))
}
