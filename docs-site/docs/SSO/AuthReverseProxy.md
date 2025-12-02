# Proposal for Reverse Proxy Authenticator

## Overview

This document proposes a centralized solution for *user identification and authorization* using **Single Sign On** configured with **OpenID PKCE**. The reverse proxy's purpose is to resolve and manage all authentication logic and expose headers to services containing user information.

## Purpose

TODO:
For now, code simplicity and centralization of authentication and security.

## Design

### Modes

The reverse proxy would operate in 2 different modes:

#### Passive Authorization

The user is not required to be signed in when accessing resources. The reverse proxy will attach user data to headers if the user is authenticated; otherwise, the request is sent as it is (or optionally with a header like `X-UserAuth: false`).

> **Note**: Passive mode is targeted for backend services that do not require authorization for every task (auth logic is handled by the service).

#### Aggressive Authorization

The user is required to be authenticated when accessing service resources.

If a user is not authenticated, the proxy will redirect to the IdP for sign-in.

> **Note**: Aggressive mode is targeted for frontend and backend services in development.



### Configuration

The protected service will have to set the following data:

* `Mode`: `passive`/`aggressive`
* `PostSignInRedirectURL` - e.g. `https://frontend/`
* `IdPSignOut`: `false`/`true`

  > This configuration makes the proxy initiate IdP SignOut together with Service SignOut.

* `PostSignOutRedirectURL` - e.g. `https://frontend/`
* `NotifyUserSession`: `false`/`true`

  > This configuration makes the proxy call a predefined route with user data after successful sign-in (the purpose is to inform the service that the user exists).

* `NotifyUserSessionURL` (required if `NotifyUserSession` is true) - e.g. `http://protected-service/api/user`
* `AttachAccessToken`: `false`/`true`

  > This configuration makes the proxy attach the access token before forwarding the request.

### Flow

#### Sign In

For sign-in, the proxy will require 2 routes: `/signIn` and `/callback`. I will not go into detail about how these work; they are part of the OpenID specification.

* `/signIn`
  This route will redirect the user to the IdP without any interaction with the protected service.

* `/callback`
  This route will redirect the user to a `PostSignInRedirectURL` (most likely a frontend URL) and initialize the user session.

After that, if `NotifyUserSession` is **true**, it will call `NotifyUserSessionURL` with the user data in the headers.

#### Sign Out

* `/signOut`

If `IdPSignOut` is **true**, this route will end the user session and then redirect to the **IdP Sign Out page** (which will redirect back to `PostSignOutRedirectURL`).

If `IdPSignOut` is **false**, this route will end the user session and then redirect to the `PostSignOutRedirectURL`.

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

It will also attach the access token if `AttachAccessToken` is **true** and refresh it if expired (with the refresh token).

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

The auth server then makes a decision:

* `2xx` - the request is OK and Traefik will forward it to the protected service (with added headers)
* otherwise, the request is rejected or redirected; the response will be the one provided by the auth server (the request does not reach the protected service)

<p align="center">
  <img src="../../img/authforward.webp" alt="Diagram" width="100%">
</p>
