# Proposal for Reverse Proxy Authenticator

## Overview

This document proposes a centralized solution for *user identification and authorization* using **Single Sign On** configured with **OpenID PKCE**. The reverse proxy's purpose is to resolve and manage all authentication logic and expose headers to services containing user information.

## Design

### Modes

The reverse proxy would operate in 2 different modes:

#### Passive Authorization

The user is not required to be signed in when accessing resources. The reverse proxy will attach user data to headers if the user is authenticated; otherwise, the request is sent as it is (or optionally with a header like `X-User-auth: false`).

> **Note**: Passive mode is targeted for backend services that do not require authorization for every task (auth logic is handled by the service).

#### Aggressive Authorization

The user is required to be authenticated when accessing service resources.

If a user is not authenticated, the proxy will redirect to the IdP for sign-in.

> **Note**: Aggressive mode is targeted for frontend and backend services in development.



### Configuration

The protected service will have to set the following data:

* `mode`: `passive`/`aggressive`

* `sign_in_path` - default: `/signIn`

* `callback_path` - default: `/callback`

* `post_sign_in_redirect_url` - e.g. `https://frontend/`

    > The path the user is redirected to after a successful sign-in

* `idp_sign_out`: `false`/`true`

    > This configuration makes the proxy initiate IdP sign-out together with the service sign-out. This means the user is also signed out from the IdP, so for the next login attempt to any website using that IdP, they will have to sign in to the IdP again.

* `post_sign_out_redirect_url` - e.g. `https://frontend/`

    > The path the user is redirected to after a successful sign-out

* `notify_user_session`: `false`/`true`

    > This configuration makes the proxy call a predefined route with user data after a successful sign-in (the purpose is to inform the service that the user exists).

* `notify_user_session_url` (required if `notify_user_session` is true) - e.g. `http://protected-service/api/user`

    > The path the proxy will call with user data after a successful sign-in

* `attach_access_token`: `false`/`true`

    > This configuration makes the proxy attach the access token before forwarding the request.

### Flow

<img src="../../img/proxy.svg"></img>

#### Sign In

For sign-in, the proxy will define 2 routes: `/${sign_in_path}` or `/signIn` and `/${callback_path}` or `/callback`. I will not go into detail about how these work; they are part of the OpenID specification.

* `/signIn`
  This route will redirect the user to the IdP without any interaction with the protected service.

* `/callback`
  This route will redirect the user to a `post_sign_in_redirect_url` (most likely a frontend URL) and initialize the user session.

After that, if `notify_user_session` is **true**, it will call `notify_user_session_url` with the user data in the headers.

#### Sign Out

* `/signOut`

If `idp_sign_out` is **true**, this route will end the user session and then redirect to the **IdP Sign Out page** (which will redirect back to `post_sign_out_redirect_url`).

If `idp_sign_out` is **false**, this route will end the user session and then redirect to the `post_sign_out_redirect_url`.

#### Any other request

For any request except the ones provided above, the proxy will read the session data (if the user is authenticated) and attach ID token claims to the request headers like so:

```json
// Headers:
"X-User-auth": true,
"X-User-sub": "93j54f2l4...",
"X-User-name": "Mihai",
"X-User-...": "..."
```

or

```json
"X-User-auth": false
```

It will also attach the access token if `attach_access_token` is **true** and refresh it if expired (with the refresh token).

```json
"Bearer Token": "3m3vjk2b..."
```

### Proxy design

The proxy will keep sessions for every authenticated user. This means the browser will contain an opaque cookie `sessionID` that is tied to some data stored on the proxy.

The proxy will store the tokens retrieved in the sign-in process (e.g. access, refresh, and ID token). It will keep this data in **Redis** (if the sessions turn out to be too many, we can offload tokens to a database like `Postgres` and cache sessions in `Redis`).

Sessions will have a rolling expiration (most probably one week). After that, they will be invalidated.

> Rolling means that the expiration resets after every user interaction.

### Compatibility with Traefik

**Traefik** supports the `forwardAuth` middleware, which offloads authentication to another server. Traefik makes a request to the authenticator server that contains the original request it received from the user.

<p align="center">
  <img src="../../img/authforward.webp" alt="Diagram" width="100%">
</p>

The auth server then makes a decision:

* `2xx` - the request is OK and Traefik will forward it to the protected service (with added headers)
* otherwise, the request is rejected or redirected; the response will be the one provided by the auth server (the request does not reach the protected service)



## Trade-offs

### Benefits

* Code simplicity: all authorization is handled by the proxy (no need for auth logic on the backend or frontend).
* Authentication changes are centralized and automatically apply to all applications.
* Consistent security across all services.
* Clear separation of concerns.
* Additional features can be added later, such as IP blocklists or rate limiting.

### Drawbacks

* Introduces a single point of failure.
* Reduced flexibility for per-application authentication requirements.
* More difficult debugging and local development.

### Mitigations

#### Hybrid mode

**Hybrid mode** is a proposal to make the transition easier for backend services.
In this mode, the proxy still performs the authorization steps, but instead of sending user data through request headers, it sends the ID token in the `Bearer` authorization header—similar to how `react-oidc-context` operates.
This means backend services would not need to change their existing authentication logic.

#### Node.js library

A significant drawback of the proxy is the difficulty of simulating the environment during local development.
My proposed mitigation is a Node.js library that simulates the proxy in development and integrates with the proxy in production.

### Conclusion

This is a large project, and this document cannot cover the entire workflow, but I hope it conveys the overall concept, intended use cases, advantages, and disadvantages.
