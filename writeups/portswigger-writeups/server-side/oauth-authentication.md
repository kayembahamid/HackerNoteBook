# OAuth Authentication

## OAuth 2.0 authentication vulnerabilities

* Web applications that allow login using social media credentials.
* The feature is built using the popular OAuth 2.0 framework.
* The framework is attractive to attackers because it's common and prone to implementation mistakes.
* It can be bypassed and leak sensitive user data if implemented incorrectly.

## OAuth

Framework which enables a web application to have limited access to a user's account on another application.

* OAuth 2.0 is the current standard.
* Some websites still use the legacy version 1.0a.
* OAuth 2.0 and 1.0a differ because they were developed differently.

### How does OAuth 2.0 work?

* Client application -> web application accessing user data
* Resource owner -> user
* OAuth service provider -> app that controls user's data to be accessed

### OAuth grant types

Grant types determine the exact sequence of steps involved in the OAuth process. These are referred to as the OAuth flow — how the client application communicates with the OAuth service at each stage.

{% stepper %}
{% step %}
### Authorization code

* A server-side flow that exchanges an authorization code for an access token via a secure server-to-server back channel (client\_secret).
* Typical sequence:
  1. Authorization request (browser redirect) Example: GET /authorization?client\_id=12345\&redirect\_uri=https://client-app.com/callback\&response\_type=code\&scope=openid%20profile\&state=ae13d489bd00e3c24 HTTP/1.1 Host: oauth-authorization-server.com
  2. User login and consent (social media account)
  3. Authorization code grant (redirect back to client) Example: GET /callback?code=a1b2c3d4e5f6g7h8\&state=ae13d489bd00e3c24 HTTP/1.1 Host: client-app.com
  4. Access token request (server-to-server POST) Example: POST /token HTTP/1.1 Host: oauth-authorization-server.com …client\_id=12345\&client\_secret=SECRET\&redirect\_uri=https://client-app.com/callback\&grant\_type=authorization\_code\&code=a1b2c3d4e5f6g7h8
  5. Access token grant Example: {"access\_token": "z0y9x8w7v6u5","token\_type": "Bearer","expires\_in": 3600,"scope": "openid profile",…}
  6. API call Example: GET /userinfo HTTP/1.1 Host: oauth-resource-server.com Authorization: Bearer z0y9x8w7v6u5
  7. Resource grant Example: {"username":"carlos","email":"carlos@carlos-montoya.net",…}
* The code/token exchange is sent server-to-server over a secure preconfigured back channel.
* Client\_secret is generated when the client application registers with the OAuth service.
{% endstep %}

{% step %}
### Implicit grant

* A browser-based flow where the access token is returned directly in a redirect, without a server-side code exchange.
* Less secure because all communication happens via browser redirects and there is no secure back-channel like in the authorization code flow.
  1. Authorization request (response\_type=token) Example: GET /authorization?client\_id=12345\&redirect\_uri=https://client-app.com/callback\&response\_type=token\&scope=openid%20profile\&state=ae13d489bd00e3c24 HTTP/1.1 Host: oauth-authorization-server.com
  2. User login and consent
  3. Access token grant (token returned in URL fragment) Example: GET /callback#access\_token=z0y9x8w7v6u5\&token\_type=Bearer\&expires\_in=5000\&scope=openid%20profile\&state=ae13d489bd00e3c24 HTTP/1.1 Host: client-app.com
  4. API call Example: GET /userinfo HTTP/1.1 Host: oauth-resource-server.com Authorization: Bearer z0y9x8w7v6u5
  5. Resource grant Example: {"username":"carlos", "email":"carlos@carlos-montoya.net"}

{% hint style="warning" %}
The implicit grant exposes the access token and user data more to potential attacks because tokens are transmitted via the browser and not exchanged via a secure server-to-server channel.
{% endhint %}
{% endstep %}
{% endstepper %}

#### OAuth Scopes

* The client application must specify:
  * Data it wants to access
    * Examples:
      * scope=contacts
      * scope=contacts.read
      * scope=contact-list-r
      * scope=https://oauth-authorization-server.com/auth/scopes/user/contacts.readonly
  * Kinds of operations to perform
    * Example scope: openid profile — grants read access to basic user information such as email address and username

## OpenID Connect

OpenID Connect (OIDC) is used to address variability in OAuth implementations by providing standardized identity-related features. It makes authentication via OAuth more reliable and uniform.

* How OpenID Connect works:
  * It slots into OAuth flows from the client application's perspective.
  * It uses a standardized set of scopes for providers and an extra response type: id\_token.
* Roles:
  1. Relying party -> application that requests authentication
  2. End user -> synonymous with the OAuth resource owner
  3. OpenID provider -> an OAuth service configured to provide OpenID features
* OpenID Connect claims and scopes:
  * Claims are key:value pairs that represent information about the user on the resource server.
* ID token:
  * A JSON Web Token (JWT) signed with a JSON Web Signature (JWS).
  * The id\_token reduces the number of requests that need to be sent between the client application and the OAuth service.

Images
