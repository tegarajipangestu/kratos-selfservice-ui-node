// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0
import {
  defaultConfig,
  logger,
  RouteCreator,
  RouteRegistrator,
  setSession,
} from "../pkg"
import { oidcConformityMaybeFakeSession } from "./stub/oidc-cert"
import { AcceptOAuth2ConsentRequestSession } from "@ory/client"
import { UserConsentCard } from "@ory/elements-markup"
import { Request, Response, NextFunction } from "express"

// Get auto-accept client IDs from environment variable
// Format: comma-separated list of client IDs that should auto-accept consent
const AUTO_ACCEPT_CLIENTS =
  process.env.AUTO_ACCEPT_CLIENT_IDS?.split(",").map((id) => id.trim()) || []
console.log(
  `Configured auto-accept clients: ${AUTO_ACCEPT_CLIENTS.join(", ") || "None"}`,
)

const extractSession = (
  req: Request,
  grantScope: string[],
): AcceptOAuth2ConsentRequestSession => {
  const session: AcceptOAuth2ConsentRequestSession = {
    access_token: {},
    id_token: {},
  }

  const identity = req.session?.identity
  if (!identity) {
    return session
  }

  // Extract standard OIDC claims
  if (grantScope.includes("email")) {
    const addresses = identity.verifiable_addresses || []
    if (addresses.length > 0) {
      const address = addresses[0]
      if (address.via === "email") {
        session.id_token.email = address.value
        session.id_token.email_verified = address.verified
      }
    }
  }

  if (grantScope.includes("profile")) {
    if (identity.traits.username) {
      session.id_token.preferred_username = identity.traits.username
    }

    if (identity.traits.website) {
      session.id_token.website = identity.traits.website
    }

    if (typeof identity.traits.name === "object") {
      if (identity.traits.name.first) {
        session.id_token.given_name = identity.traits.name.first
      }
      if (identity.traits.name.last) {
        session.id_token.family_name = identity.traits.name.last
      }
    } else if (typeof identity.traits.name === "string") {
      session.id_token.name = identity.traits.name
    }

    if (identity.updated_at) {
      session.id_token.updated_at = parseInt(
        (Date.parse(identity.updated_at) / 1000).toFixed(0),
      )
    }
  }

  return session
}

// A simple express handler that shows the Hydra consent screen.
export const createConsentRoute: RouteCreator =
  (createHelpers) =>
  async (req: Request, res: Response, next: NextFunction) => {
    res.locals.projectName = "Consent"
    const { oauth2, isOAuthConsentRouteEnabled, logoUrl, identity } =
      createHelpers(req, res)

    if (!isOAuthConsentRouteEnabled()) {
      res.redirect("404")
      return
    }

    // The challenge is used to fetch information about the consent request from ORY Hydra.
    const challenge = String(req.query.consent_challenge)
    if (!challenge) {
      next(
        new Error("Expected a consent challenge to be set but received none."),
      )
      return
    }

    // Let's check if ory hydra deployed at the HYDRA_ADMIN_URL environment variable, if not fallback to ORY_SDK_URL
    oauth2
      .getOAuth2ConsentRequest({ consentChallenge: challenge })
      // This will be called if the HTTP request was successful
      .then(async ({ data: body }) => {
        // If a user has authenticated with Ory Kratos, they'll have a session cookie from Kratos. And, if it was set to remember them,
        // they'll have a long-lived cookie. We don't need to check that here though, we just need to make sure
        // that Hydra still considers their login valid.

        // If consent can't be skipped we will redirect the browser to the consent UI
        const clientId = body.client?.client_id
        const clientName = body.client?.client_name || "Unknown Client"
        const requestedScopes = body.requested_scope || []
        const clientMetadata =
          (body.client?.metadata as Record<string, any>) || {}

        // Check if this client ID should auto-accept consent based on environment variable
        const shouldAutoAccept =
          clientId && AUTO_ACCEPT_CLIENTS.includes(clientId)

        console.log("Consent decision for client", {
          client_id: clientId,
          client_name: clientName,
          hydra_says_skip: body.skip,
          auto_accept_client: shouldAutoAccept,
          will_skip_consent: body.skip || shouldAutoAccept,
        })

        // Check if skip is true from Hydra or if client is in auto-accept list
        if (body.skip || shouldAutoAccept) {
          // But if are able to skip it, let's go ahead and grant the requested scopes
          // Either Hydra told us to skip the consent screen or the client ID is in our auto-accept list
          const skipReason = body.skip
            ? "Hydra skip flag"
            : "auto-accept client list"
          console.log(`Consent request will be skipped (reason: ${skipReason})`)

          const grantScope = body.requested_scope || []
          const session = extractSession(req, grantScope)

          // Add Google OIDC tokens if we have an identity
          if (req.session?.identity?.id) {
            try {
              // Call the admin API to get the identity with OIDC credentials
              console.log(
                "Fetching identity with OIDC credentials for auto-consent",
                {
                  identityId: req.session.identity.id,
                },
              )

              const { data: identityDetails } = await identity.getIdentity({
                id: req.session.identity.id,
                includeCredential: ["oidc"],
              })

              // Log the identity traits to debug if Google attributes exist
              console.log("Identity traits retrieved from Kratos:", {
                has_traits: !!identityDetails.traits,
                trait_keys: identityDetails.traits
                  ? Object.keys(identityDetails.traits)
                  : [],
                google_sub: identityDetails.traits?.google_sub,
                name: identityDetails.traits?.name,
                email: identityDetails.traits?.email,
              })

              // Extract OIDC credentials if they exist
              if (identityDetails.credentials?.oidc?.config) {
                // Cast to appropriate type since we know the structure from the API
                const oidcConfig = identityDetails.credentials.oidc.config as {
                  providers?: Array<{
                    provider: string
                    initial_id_token?: string
                    initial_access_token?: string
                    initial_refresh_token?: string
                  }>
                }

                // Find Google provider if it exists
                const googleProvider = oidcConfig.providers?.find(
                  (p) => p.provider === "google",
                )

                if (googleProvider) {
                  console.log("Found Google OIDC provider for auto-consent")

                  if (!session.access_token.google) {
                    session.access_token.google = {}
                  }

                  if (googleProvider.initial_id_token) {
                    session.access_token.google.google_id_token =
                      googleProvider.initial_id_token
                  }

                  if (googleProvider.initial_access_token) {
                    session.access_token.google.google_access_token =
                      googleProvider.initial_access_token
                  }

                  if (googleProvider.initial_refresh_token) {
                    session.access_token.google.google_refresh_token =
                      googleProvider.initial_refresh_token
                  }

                  if (identityDetails.traits?.google_sub) {
                    session.access_token.google.sub =
                      identityDetails.traits.google_sub
                    session.access_token.google.name =
                      identityDetails.traits.name
                    session.access_token.google.email =
                      identityDetails.traits.email

                    console.log("Added Google subject ID to consent session", {
                      google_sub: identityDetails.traits.google_sub,
                    })
                  }

                  console.log("Added Google tokens to auto-consent session", {
                    has_id_token: !!googleProvider.initial_id_token,
                    has_access_token: !!googleProvider.initial_access_token,
                    has_refresh_token: !!googleProvider.initial_refresh_token,
                  })
                }
              }
            } catch (error) {
              console.log("Error retrieving Google tokens for auto-consent", {
                error,
              })
              // Continue with base session data even if token retrieval fails
            }
          }

          // Now it's time to grant the consent request. We could also deny the request if something went terribly wrong
          return oauth2
            .acceptOAuth2ConsentRequest({
              // To accept the consent request, we need to pass the challenge to Hydra
              consentChallenge: challenge,

              // ORY Hydra checks if requested audiences are allowed by the client, so we can simply echo this.
              acceptOAuth2ConsentRequest: {
                grant_scope: grantScope,

                // The session allows us to set session data for id and access tokens
                // Using the oidcConformityMaybeFakeSession wrapper for test compatibility
                session: oidcConformityMaybeFakeSession(grantScope, session),

                // ORY Hydra checks if requested audiences are allowed by the client, so we can simply echo this.
                grant_access_token_audience:
                  body.requested_access_token_audience,

                // This tells hydra to remember this consent request and allow the same client to request the same
                // scopes from the same user, without showing the UI, in the future.
                remember: true,

                // When this is set, the consent will be remembered for 1 hour
                remember_for: 3600,
              },
            })
            .then(({ data: body }) => {
              console.log("Consent request was accepted")
              // All we need to do now is to redirect the user back to hydra!
              res.redirect(String(body.redirect_to))
            })
            .catch(next)
          return
        }

        // this should never happen
        if (!req.csrfToken) {
          logger.warn(
            "Expected CSRF token middleware to be set but received none.",
          )
          next(
            new Error(
              "Expected CSRF token middleware to be set but received none.",
            ),
          )
          return
        }

        // If consent can't be skipped we MUST show the consent UI.
        res.render("consent", {
          card: UserConsentCard({
            consent: body,
            csrfToken: req.csrfToken(true),
            cardImage: body.client?.logo_uri || logoUrl,
            client_name:
              body.client?.client_name ||
              body.client?.client_id ||
              "Unknown Client",
            requested_scope: body.requested_scope || [],
            client: body.client,
            action: "consent",
          }),
        })
      })
      // This will handle any error that happens when making HTTP calls to hydra
      .catch(next)
    // The consent request has now either been accepted automatically or rendered.
  }

export const createConsentPostRoute: RouteCreator =
  (createHelpers) => async (req, res, next) => {
    res.locals.projectName = "Consent"
    // The challenge is a hidden input field, so we have to retrieve it from the request body
    const { oauth2, isOAuthConsentRouteEnabled, identity } = createHelpers(
      req,
      res,
    )

    if (!isOAuthConsentRouteEnabled()) {
      res.redirect("404")
      return
    }

    const {
      consent_challenge: challenge,
      consent_action,
      remember,
      grant_scope,
    } = req.body

    let grantScope = grant_scope
    if (!Array.isArray(grantScope)) {
      grantScope = [grantScope]
    }

    // First get the base session data from the request
    const session = extractSession(req, grantScope)

    // Add Google OIDC tokens if we have an identity
    if (req.session?.identity?.id) {
      try {
        // Call the admin API to get the identity with OIDC credentials
        console.log("Fetching identity with OIDC credentials for consent", {
          identityId: req.session.identity.id,
        })

        const { data: identityDetails } = await identity.getIdentity({
          id: req.session.identity.id,
          includeCredential: ["oidc"],
        })

        // Extract OIDC credentials if they exist
        if (identityDetails.credentials?.oidc?.config) {
          // Cast to appropriate type since we know the structure from the API
          const oidcConfig = identityDetails.credentials.oidc.config as {
            providers?: Array<{
              provider: string
              initial_id_token?: string
              initial_access_token?: string
              initial_refresh_token?: string
            }>
          }

          // Find Google provider if it exists
          const googleProvider = oidcConfig.providers?.find(
            (p) => p.provider === "google",
          )

          if (googleProvider) {
            console.log("Found Google OIDC provider for consent")

            if (!session.access_token.google) {
              session.access_token.google = {}
            }

            if (googleProvider.initial_id_token) {
              session.access_token.google.google_id_token =
                googleProvider.initial_id_token
            }

            if (googleProvider.initial_access_token) {
              session.access_token.google.google_access_token =
                googleProvider.initial_access_token
            }

            if (googleProvider.initial_refresh_token) {
              session.access_token.google.google_refresh_token =
                googleProvider.initial_refresh_token
            }

            // Add Google subject ID from identity traits if available
            if (identityDetails.traits?.google_sub) {
              session.access_token.google.sub =
                identityDetails.traits.google_sub
              session.access_token.google.name = identityDetails.traits.name
              session.access_token.google.email = identityDetails.traits.email

              console.log("Added Google subject ID to consent session", {
                google_sub: identityDetails.traits.google_sub,
              })
            }

            console.log("Added Google tokens to consent session", {
              has_id_token: !!googleProvider.initial_id_token,
              has_access_token: !!googleProvider.initial_access_token,
              has_refresh_token: !!googleProvider.initial_refresh_token,
            })
          }
        }
      } catch (error) {
        logger.error("Error retrieving Google tokens for consent", { error })
        // Continue with base session data even if token retrieval fails
      }
    }

    // Let's fetch the consent request again to be able to set `grantAccessTokenAudience` properly.
    // Let's see if the user decided to accept or reject the consent request..
    if (consent_action === "accept") {
      console.log("Consent request was accepted by the user")
      await oauth2
        .getOAuth2ConsentRequest({
          consentChallenge: String(challenge),
        })
        .then(async ({ data: body }) => {
          return oauth2
            .acceptOAuth2ConsentRequest({
              consentChallenge: String(challenge),
              acceptOAuth2ConsentRequest: {
                // We can grant all scopes that have been requested - hydra already checked for us that no additional scopes
                // are requested accidentally.
                grant_scope: grantScope,

                // ORY Hydra checks if requested audiences are allowed by the client, so we can simply echo this.
                grant_access_token_audience:
                  body.requested_access_token_audience,

                // If the environment variable CONFORMITY_FAKE_CLAIMS is set we are assuming that
                // the app is built for the automated OpenID Connect Conformity Test Suite.
                // Otherwise, use our session with Google tokens included
                session: oidcConformityMaybeFakeSession(grantScope, session),

                // Remember the consent
                // scopes from the same user, without showing the UI, in the future.
                remember: Boolean(remember),

                // When this "remember" sesion expires, in seconds. Set this to 0 so it will never expire.
                remember_for: process.env.REMEMBER_CONSENT_SESSION_FOR_SECONDS
                  ? Number(process.env.REMEMBER_CONSENT_SESSION_FOR_SECONDS)
                  : 3600,
              },
            })
            .then(({ data: body }) => {
              const redirectTo = String(body.redirect_to)
              console.log("Consent request successfuly accepted", redirectTo)
              // All we need to do now is to redirect the user back!
              res.redirect(redirectTo)
            })
        })
        .catch(next)
      return
    }

    console.log("Consent request denied by the user")

    // Looks like the consent request was denied by the user
    await oauth2
      .rejectOAuth2ConsentRequest({
        consentChallenge: String(challenge),
        rejectOAuth2Request: {
          error: "access_denied",
          error_description: "The resource owner denied the request",
        },
      })
      .then(({ data: body }) => {
        // All we need to do now is to redirect the browser back to hydra!
        res.redirect(String(body.redirect_to))
      })
      // This will handle any error that happens when making HTTP calls to hydra
      .catch(next)
  }

export const registerConsentRoute: RouteRegistrator = (
  app,
  createHelpers = defaultConfig,
) => {
  app.get(
    "/consent",
    setSession(createHelpers),
    createConsentRoute(createHelpers),
  )
  app.post(
    "/consent",
    setSession(createHelpers),
    createConsentPostRoute(createHelpers),
  )
}
