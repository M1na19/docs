# OpenID Connect Authorization Design

## Introduction

This document captures my exploration of authentication flows, common pitfalls, and security best practices related to user authorization.

### Purpose

The goal of this document is not to prescribe a single “correct” authentication flow. Instead, it aims to highlight security considerations, potential vulnerabilities, and trade-offs involved in different design patterns.

### Scope

* OpenID Connect (OIDC) authorization flows
* XSS and CSRF risks and their implications in authorization
* Design trade-offs and security considerations

## Authorization Flows in OIDC / OpenID Connect

### Notations:
* `IdP` - stands for Identity Provider, it is the server that handles authentication (e.g. Google SSO, LSAC SSO etc. )
* `Client` - refering to the SSO Client, the application that uses the authentication provided by the `IdP`
* `User`/`End-User` - you


### How JWT Tokens Work

If you are already familiar with **JWTs**, you can skip this section.

JWT (JSON Web Token) is a type of token commonly used for authentication and authorization. It not only conveys information but also ensures the integrity of that information through signatures. A JWT is composed of three parts:

### 1. Header

The header specifies the cryptographic algorithm used to sign the token and other metadata.

**Example:**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### 2. Payload

The payload contains claims—information about the user or session.

**Example:**

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022
}
```

### 3. Signature

The signature ensures that the token has not been tampered with.

In SSO scenarios, **asymmetric signing** is typically used. The Identity Provider (IdP) signs the JWT with its **private key**, and anyone with the **public key** can verify it:

```js
// Creating a signature
signature = Encrypt(private_key, header + '.' + payload)

// Verifying a signature
header + '.' + payload === Decrypt(public_key, signature)
```

Alternatively, **symmetric signing** uses a shared secret known only to the IdP:

```js
// Creating a signature
signature = Hash(secret, header + '.' + payload)

// Verifying a signature
Hash(secret, header + '.' + payload) === signature
```

> **Important:** If the secret is compromised, an attacker could generate valid JWTs and impersonate any user. This is why private key management and secure signing practices are critical.

### The Purpose of Access, Refresh, and ID Tokens

Access, Refresh, and ID tokens are all commonly implemented as **JWTs**, but each serves a distinct purpose in the authentication and authorization process:

1. **ID Token**

   * Contains information about the authenticated user, such as user ID, name, and email.
   * Used by the client to identify the end-user and establish a session.

   **Example:**

   ```json
   {
     "sub": "1234567890",
     "name": "John Doe",
     "email": "john.doe@example.com",
     "iat": 1516239022,
     "exp": 1516242622
   }
   ```

2. **Access Token**

   * Short-lived token used to authorize API requests on behalf of the user.
   * Typically sent in the `Authorization` header as a bearer token.

3. **Refresh Token**

   * Long-lived token used to obtain new access tokens when they expire.
   * Can also be used to refresh itself in some flows, depending on the IdP.
   * Must be stored securely (server-side or in httpOnly cookies) because it can be used to gain new access tokens indefinitely.

### Implicit Authorization Flow

The [Implicit Flow](https://auth0.com/docs/authenticate/login/oidc-conformant-authentication/oidc-adoption-implicit-flow) was originally designed for SPAs where a client secret could not be safely stored. It is now considered **deprecated and insecure**.

<p align="center">
  <img src="./implicit.png" alt="Diagram" width="400">
</p>

#### Steps
1. User initiates sign in, makes a request to the client - ex: `https://example.ro/signIn`
2. Client redirects user to the Identity Provider (IdP) - ex: `https://sso.ro/signIn`
3. User logs in with credentials.
4. After successful authentication, the IdP redirects the user back to the client with **access** and **ID** tokens directly in the redirect (usually in the URL fragment) - ex: `https://example.ro?accessToken=...&idToken=...`

#### Problems

* Tokens can appear in browser history or logs.
* SPAs expose tokens to JavaScript, making them vulnerable to XSS.
* No server-side token exchange step.

### [Authorization Code Flow](https://auth0.com/docs/authenticate/login/oidc-conformant-authentication/oidc-adoption-auth-code-flow)

The [Authorization Code Flow](https://auth0.com/docs/authenticate/login/oidc-conformant-authentication/oidc-adoption-auth-code-flow) improves security by returning only an *authorization code* to the client. The client must then exchange it for tokens.


<p align="center">
  <img src="./code.png" alt="Diagram" width="400">
</p>

#### Steps

1. User initiates sign in, makes a request to the client - ex: `https://example.ro/signIn`
2. Client redirects user to the Identity Provider (IdP) - ex: `https://sso.ro/signIn`
3. User logs in with credentials.
4. The IdP redirects user back to Client with an **authorization code** - ex: `https://example.ro?authCode=...&iss=...`
5. The Client can then exchange the code for tokens (`access token`, `id token`, sometimes `refresh token`). The IdP provides a route - ex: `https://sso.ro/tokens`.
```json
body: {
  "code": AUTH_CODE, // from IdP callback
  ...
}
```
> Note: Depending on the type of application these tokens can be used directly or the Client can issue new tokens or sessions

#### Problems

* Without PKCE, the code can be intercepted and misused.
* Storing tokens directly in a SPA still carries the same exposure risks as the implicit flow.

### [Authorization Code Flow with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce)

The [Authorization Code Flow with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce) adds protection against code interception. PKCE ensures continuity between the initial redirect and the code-exchange step.

<p align="center">
  <img src="./code.png" alt="Diagram" width="400">
</p>

#### Steps

1. User initiates sign in, makes a request to the client - ex: `https://example.ro/signIn`
  - The client generates a cryptographically random **code verifier** - random string.
  - The client derives a **code challenge** from the verifier (typically a SHA-256 hash). 
  - The client sends the **code challenge** along with the authorization request.
2. Client redirects user to the Identity Provider (IdP) with code challange - ex: `https://sso.ro/signIn?code_challange=....`
3. After successful authentication, the IdP redirects the user back with the **authorization code** - ex: `https://example.ro?authCode=...&iss=...`
4. The client exchanges the authorization code **together with the original code verifier** - ex: `https://https://sso.ro/token`
```json
body:{
  "code": AUTH_CODE,// auth code from callback
  "code_verifier": CODE_VERIFIER,
  "client_id": CLIENT_ID
  ... // there is other data included such as client secret, redirect uri etc.
}
```
5. The IdP checks that the code verifier corresponds to the previously sent code challenge, and if valid, issues tokens.

> **Note:** The IdP does *not* send the code challenge back to the client. The client must remember the verifier locally.

## Cross-Site Scripting (XSS)

To understand why storing tokens in a Single Page Application (SPA) is discouraged, it’s important to first understand **Cross-Site Scripting (XSS)**. XSS occurs when an attacker injects malicious JavaScript into a website, which then executes in another user’s browser.

This vulnerability has two key components:

1. **The server accepts malicious input**

   This is a broad category: malicious input may include raw HTML, SVG files, or anything that can contain executable JavaScript. The critical factor is that this input can later be accessed or rendered by other users.

2. **The server returns that malicious input to other users**

   When the injected content is delivered to another user’s browser and executed, the attack is successful. At that point, the attacker can access user credentials, tokens, session data, or perform arbitrary actions on behalf of the user.

### Mitigations

* **Sanitize and encode user input**

  Frameworks like **React** automatically HTML-encode any content placed in `{}` expressions, preventing raw HTML from rendering unless explicitly allowed via `dangerouslySetInnerHTML`.

* **Avoid rendering powerful HTML elements using untrusted data**

  Elements such as:

  ```html
  <iframe></iframe>
  <embed></embed>
  <script></script>
  ```

  should never be populated from user-controlled sources, as they allow direct execution of arbitrary content.

* **Enforce strict formats on user-uploaded files**

  For file uploads—whether stored in S3 or on local disk—restrict the allowed file types and validate the actual file contents (MIME sniffing), not just the extension. Do not permit arbitrary formats such as SVGs or HTML files unless absolutely required.

* **Use Content Security Policy (CSP)**

  A strong CSP can significantly reduce the impact of XSS by blocking inline scripts and limiting where scripts can load from.

* **Avoid dangerous APIs**

  Functions such as `innerHTML`, `document.write`, and `eval` dramatically increase XSS risk and should not be used with untrusted data.


## SPA Token Storage

For applications that require strong security guarantees, relying on SPA token storage is discouraged.
In SPAs, tokens cannot be stored in **httpOnly** cookies—meaning they must be stored in JavaScript-accessible storage (localStorage/sessionStorage).

#### Vulnerabilities

* **XSS** can steal tokens.
* Any malicious script running in the browser can access the stored tokens.

## React SPA Flow

Libraries like [react-oidc-context](https://github.com/authts/react-oidc-context), built on top of [oidc-client-ts](https://github.com/authts/oidc-client-ts), provide OIDC support specifically for **SPA** React applications.
They use Authorization Code Flow with PKCE but store tokens in `localStorage` or `sessionStorage`, making them inherently vulnerable to token theft if an XSS occurs.

## Backend Auth Code Flow with PKCE

Using the Authorization Code Flow with PKCE on the **backend** reduces the attack surface significantly. The main remaining question is how tokens should be stored once the backend obtains them.

## Option 1: Store Access and ID Token on the Frontend as httpOnly Cookies

Storing tokens in **httpOnly** cookies is technically secure from a browser-accessibility standpoint. However, this pattern is generally avoided due to the principles of:

* **Isolation** – The frontend should not automatically gain access to all user identity and authorization information.
* **Least Privilege** – The user should only receive the minimum data needed to function.

Instead of placing access/ID/refresh tokens directly in cookies, it is considered best practice to issue a **session identifier**. This allows the backend to control exactly what information is delivered to the frontend and avoids exposing raw tokens to the browser at all.

## Option 2: Session Cookie (Recommended)

A session cookie is an **httpOnly**, typically **secure**, cookie that stores only a random, opaque identifier.
This identifier maps to server-side session data that the backend controls.


<p align="center">
  <img src="./flow.png" alt="Diagram" width="400">
</p>

### Flow

Alongside the standard PKCE authentication flow:

1. User initiates sign in, makes a request to the client - ex: `https://example.ro/signIn`
2. Before redirecting the user to the IdP, the client creates a **session** and stores the generated **code verifier** inside it.
3. The user signs in with credentials on the IdP.
4. After the callback, the backend uses:
   * the **authorization code** from the redirect, and
   * the **code verifier** retrieved from the session to exchange for tokens.
5. The client stores relevant user information in the session (derived from its database or from ID token claims, depending on architecture).
6. The frontend receives only the session cookie.
7. Any interaction between the user and client is done through this session cookie.

### Sudo Mode

Many providers (e.g., GitHub, Google, AWS) implement **sudo mode**, a mechanism that enforces authentication freshness for sensitive operations.

**Key Behaviors**

* High-risk actions (such as deletions, privilege changes, or configuration updates) require a recently authenticated session.
* If the current session is older than the defined freshness window (typically several hours), the user must reauthenticate through SSO before the action is allowed.
* Normal, low-risk actions continue to function without requiring reauthentication.


## Cross-Site Request Forgery (CSRF)

Now that the application is mostly secure, we must consider another subtle vulnerability introduced when switching to cookie-based authentication. Previously, when tokens were stored in `localStorage` or `sessionStorage`, they had to be manually added to the `Authorization` header for each request. This *implicitly* protected against CSRF, because the browser could not automatically attach those tokens.

CSRF occurs when a user, often through social engineering, is tricked into making unintended requests to a site where they are already authenticated. For example, a malicious website could include:

```html
<form action="https://site.i.am.logged.in.to/pay_100_dolars" method="POST">
  <!-- auto-submitted via JavaScript -->
</form>
```

If the target site uses cookies for authentication, and these cookies are sent automatically (`SameSite=None`), the browser will attach them to the request, even though the user never intended to perform the action.

### Mitigations

* **Set cookies with `SameSite=Lax` or `SameSite=Strict`**

  These settings prevent cookies from being sent on cross-site requests. `Lax` blocks most cross-site POST requests, while `Strict` blocks all cross-site navigations.

* **Use CSRF tokens**

  CSRF tokens are unpredictable values generated by the server and included in forms or API requests. Since they must be added manually via JavaScript (or injected into the page), the browser cannot include them automatically. This ensures that a cross-site request made by an attacker will be missing the required token.

This mirrors how SPA authentication used to work: access tokens stored in browser storage had to be manually attached as headers, making them functionally similar to CSRF tokens. That is why traditional SPA token-based workflows generally did not require separate CSRF protection, the token itself served that purpose.

### CSRF Tokens

This topic can quickly get deep, so here is a concise overview of the two common approaches for implementing CSRF protection:

1. **Session-based tokens (stateful)**

The server stores a CSRF token in the user’s session. For any non-`GET` request (`POST`, `PUT`, `DELETE`), the frontend must include the token, usually in a header or hidden form field.
The server validates that the provided token matches the one stored in the session.

2. **Double-cookie tokens (stateless)**

This method avoids storing tokens on the server. Instead, the backend issues a CSRF token to the frontend as a cookie. When the user makes an API request, the token is sent twice:

* once automatically by the browser via the cookie
* once manually in a request header set by JavaScript

The server compares the two values. If they match, the request is allowed.

> **Note:** The token must be *signed* by the server (HMAC) to ensure it was issued by the backend and not forged by an attacker.

## Tradeoffs

Adopting backend-managed PKCE authorization increases security but introduces new considerations.

### Complexity

* Each backend client must manage server-side sessions.
* Each backend must implement the Authorization Code Flow with PKCE (including code-verifier persistence, code exchange, token handling, refresh logic, etc.).
* Session lifecycle management (expiration, rotation, revocation) becomes part of the backend.
* There must be introduced CSRF protections
### Resource Usage

* **Compute**:
  The server performs the token exchange and additional authorization logic that would otherwise run in the client.
* **Storage / Memory**:
  Session data must be persisted for all authenticated users.
  This is commonly offloaded to distributed stores such as **Redis**, especially in horizontally scaled environments.

### Conclusion

Implementing secure authorization flows comes with many pitfalls. Strengthening security in one area can inadvertently expose weaknesses elsewhere, and in general, higher security often comes with increased complexity and resource requirements. While no approach is perfect, this document highlights key best practices and trade-offs to consider when designing SSO authorization.