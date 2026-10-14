# OAuth

The `oauth` plugin signs a user in through an OAuth 2.0 or OpenID Connect provider, such as Google or GitHub. The provider authenticates the user, and Behemoth signs in the user the provider names, or creates one on the first sign-in.

Three kinds of provider ship with the plugin and are configured as data: any OpenID Connect provider, Google, and GitHub. You can add a provider of your own.

`Experimental:` the plugin does not link a provider account to a user who already exists, and it does not store the provider's tokens. Its API can still change.

## How it works

| Step | Who | What happens |
| --- | --- | --- |
| 1 | your page | posts the provider's id to `POST /sign-in/oauth` |
| 2 | plugin | stores the sign-in, and answers with the provider's authorization URL and a binding value |
| 3 | your page | sends the browser to the authorization URL |
| 4 | user | signs in at the provider |
| 5 | provider | sends the browser to your callback page, with a `code` and a `state` in the URL |
| 6 | your callback page | posts the code, the state, and the binding value to `POST /oauth/complete` |
| 7 | plugin | checks the state and the binding value, redeems the code at the provider, and creates a session |

The provider sends the browser to your page and not to Behemoth, and every call to Behemoth is a JSON `POST`. A sign-in therefore answers like every other sign-in route, whichever session transport you use.

The binding value ties step 7 to the client that made step 1. A browser that is sent to your callback page with somebody else's code and state does not have it, so the sign-in is refused.

## Setup

Pass the plugin to `Prepare`. It uses the core `users`, `accounts`, `sessions`, and `tokens` tables and has none of its own.

```go
import (
	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/plugins/oauth"
)

plugin := oauth.New(oauth.Options{
	Providers: []oauth.ProviderConfig{{
		Kind:         oauth.KindGoogle,
		ClientID:     "1234.apps.googleusercontent.com",
		ClientSecret: crypto.StaticSecretSource{Secrets: map[int]string{1: GOOGLE_CLIENT_SECRET}, Current: 1},
	}},
	CallbackURL: "https://app.example.com/auth/callback",
})

app, err := bmth.Prepare([]types.Plugin{plugin}, bmth.PrepareConfig{})
// ...
ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{
	Router: types.RouterConfig{TrustedOrigins: []string{"https://app.example.com"}},
	// ...
})
```

Replace `GOOGLE_CLIENT_SECRET` with the client secret, read from where you keep secrets.

Register the redirect URI of each provider at the provider. It is `CallbackURL`, then `/`, then the provider's id. `oauth.RedirectURI(callbackURL, id)` returns it:

```go
oauth.RedirectURI("https://app.example.com/auth/callback", "google")
// "https://app.example.com/auth/callback/google"
```

Serve your callback page at that URI. See [Build the callback page](#build-the-callback-page).

## Options

| Field | Default | Meaning |
| --- | --- | --- |
| `Providers` | none | The built-in providers a user can sign in with, as data. See [Configure a provider](#configure-a-provider). |
| `CustomProviders` | none | Providers you implement. See [Write a provider](#write-a-provider). |
| `CallbackURL` | required | The page of your application the providers send the browser back to. Absolute, `http` or `https`, without a query or a fragment. Each provider's redirect URI is below it. |
| `StateTTL` | 10 minutes | How long a started sign-in can be completed: the time a user has at the provider. `TokenConfig.TTLOverrides[types.TokenKindOAuthState]` takes precedence. |
| `HTTPClient` | a client with a 10-second timeout that follows no redirect | The client the built-in providers call the provider with. Set it for an outbound proxy. A client of your own should not follow redirects either: the code exchange sends the client secret. |

`Boot` returns a configuration error for no provider at all, a `ProviderConfig` that is incomplete or whose secret can't be read, a nil provider, an id that is used twice, an id that is not 1 to 64 characters of `a-z`, `0-9`, `-`, and `_`, the id `credential`, and a `CallbackURL` that is not usable. `Boot` calls no provider. A provider that is down fails its sign-ins, not the boot.

## Configure a provider

A `ProviderConfig` describes one built-in provider:

| Field | Meaning |
| --- | --- |
| `Kind` | `oauth.KindOIDC`, `oauth.KindGoogle`, or `oauth.KindGitHub`. Required. |
| `ID` | The provider's id. It defaults to the kind for Google and GitHub, and is required for `KindOIDC`, such as `"okta"`. It is stored with every account the provider signs in, so don't change it once users have signed in. |
| `ClientID` | The client id the provider issued to your application. Required. |
| `ClientSecret` | A `types.SecretSource` with the client secret. Its current secret is used. Required for Google and GitHub. Without it, a `KindOIDC` provider is a public client and authenticates with PKCE alone. |
| `Issuer` | The issuer of a `KindOIDC` provider, such as `"https://login.example.com"`. Required for `KindOIDC`, and empty for the other two. It is `https`, or `http` on `localhost` or a loopback address, and it has to be exactly the issuer the provider's discovery document names. |
| `Scopes` | Replaces the kind's scopes. An OpenID Connect provider needs `openid`. |

The kinds differ as follows:

| Kind | Scopes by default | Where the user comes from |
| --- | --- | --- |
| `KindOIDC` | `openid email profile` | the ID token. When it has no email, the issuer's userinfo endpoint. |
| `KindGoogle` | `openid email profile` | the ID token, as for `KindOIDC`, with the issuer `https://accounts.google.com` |
| `KindGitHub` | `read:user user:email` | GitHub's API. The subject is the user's numeric id, because a login can be renamed. The email is the primary address, and only when GitHub verified it. Without `user:email`, the identity has no email. |

The plugin reads the client secret at `Boot`, and again for every code it redeems. To rotate a secret, make the new one current in the source. No restart is needed.

### What the built-in providers check

The plugin calls an OpenID Connect provider's discovery document at the first sign-in, and every 24 hours after. It refuses a document that names another issuer, or an endpoint that is not `https`.

An ID token is accepted only when every one of these checks passes:

- **The signature.** A key of the issuer's key set, with RSA (at least 2048 bits) or ECDSA. `none` and the HMAC algorithms are refused. The key set is kept for an hour. A token signed with a key the set lacks makes the plugin fetch the set again, at most once a minute.
- **The issuer, the audience, and the authorized party.** `iss` is the issuer, `aud` names your client id, and `azp`, when present or when there are several audiences, is your client id.
- **The time.** `exp` is required, and neither `exp` nor `iat` may be off by more than a minute.
- **The nonce and the subject.** `nonce` is the one of the sign-in, and `sub` is not empty.

When the provider sends an `iss` parameter with the code (RFC 9207), it has to be the issuer. When the discovery document says the provider sends one, it is required. See [Build the callback page](#build-the-callback-page).

The token request authenticates with HTTP Basic when the provider supports it or does not say, and in the form otherwise. GitHub gets the secret in the form. A provider's answer is read up to 1 MiB.

## Write a provider

For a provider that is not built in, implement `Provider` and pass it in `CustomProviders`. A `Provider` has an id and two methods:

| Method | Receives | Returns |
| --- | --- | --- |
| `ID()` | | The provider's id. It is stored with every account the provider signs in, so don't change it once users have signed in. |
| `AuthorizationURL(ctx, req)` | the state, the redirect URI, the PKCE code challenge (S256), and the nonce | The URL at the provider to send the browser to. Absolute, `http` or `https`. |
| `Exchange(ctx, req)` | the authorization code, the redirect URI, the PKCE code verifier, the nonce, and the `iss` parameter when the provider sent one | An `ExchangeResult` with the user's `Identity`. |

An `Identity` has these fields:

| Field | Meaning |
| --- | --- |
| `Subject` | The provider's stable id for the user. Required. Never an email address. |
| `Email` | The user's email address at the provider. Optional for a user who already has an account, required on the first sign-in. |
| `EmailVerified` | `true` only when the provider says it verified `Email`. |
| `Name`, `GivenName`, `FamilyName` | The user's name. Each is optional. |
| `Picture` | The URL of the user's picture. Optional. |

`Exchange` reports a refusal by returning an error that wraps `oauth.ErrExchangeRefused`: a code the provider refused, or an ID token that fails your checks. The plugin then refuses the sign-in with `invalid_oauth_callback`. Any other error is a failure of the system, and the route answers `500`.

Put the code challenge and the nonce into the authorization URL, and send the verifier with the code. The plugin creates them for every sign-in, but it can't check that your provider uses them. Without them, an authorization code that leaks can be used by somebody else.

```go
type acmeProvider struct {
	clientID string
	// redeem posts the code, the redirect URI, and the verifier to Acme's
	// token endpoint, checks the ID token's signature, issuer, audience,
	// and expiry, and returns its claims.
	redeem func(ctx context.Context, req oauth.ExchangeRequest) (map[string]any, error)
}

func (p *acmeProvider) ID() string { return "acme" }

func (p *acmeProvider) AuthorizationURL(ctx context.Context, req oauth.AuthorizationRequest) (string, error) {
	query := url.Values{
		"response_type": {"code"}, "client_id": {p.clientID}, "scope": {"openid email profile"},
		"redirect_uri": {req.RedirectURI}, "state": {req.State}, "nonce": {req.Nonce},
		"code_challenge": {req.CodeChallenge}, "code_challenge_method": {"S256"},
	}
	return "https://id.acme.example/authorize?" + query.Encode(), nil
}

func (p *acmeProvider) Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.ExchangeResult, error) {
	claims, err := p.redeem(ctx, req)
	if err != nil {
		return nil, err // wrap oauth.ErrExchangeRefused when Acme refused the code
	}
	if claims["nonce"] != req.Nonce {
		return nil, fmt.Errorf("acme: the ID token has another nonce: %w", oauth.ErrExchangeRefused)
	}
	subject, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	verified, _ := claims["email_verified"].(bool)
	return &oauth.ExchangeResult{Identity: oauth.Identity{Subject: subject, Email: email, EmailVerified: verified}}, nil
}
```

A provider must be safe for concurrent use.

## Build the callback page

Your callback page receives the browser at `<CallbackURL>/<provider id>`, with `code` and `state` in the query, and `iss` when the provider sends it. It posts them to `POST /oauth/complete` with the provider's id, the last segment of its own path.

The binding value comes back the way it went out:

| Session transport | `POST /sign-in/oauth` returns the binding value | Your page sends it back |
| --- | --- | --- |
| `TransportCookie`, the default | in an `HttpOnly` cookie. The body has no `binding`. | The browser sends the cookie. Call with `credentials: "include"` when Behemoth is on another origin. |
| `TransportHeader`, `TransportBody` | in the body, as `binding` | Keep it where the page can read it after the redirect, such as `sessionStorage`, and send it as `binding`. |
| `TransportBoth` | in both | Either way. |

Never put the binding value in a URL. Whoever has the code, the state, and the binding value can complete the sign-in.

```js
// On your sign-in page.
const begun = await fetch("/api/auth/sign-in/oauth", {
  method: "POST", credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ provider: "google", redirect_url: "/dashboard" }),
}).then((r) => r.json());
if (begun.binding) sessionStorage.setItem("oauth_binding", begun.binding); // header and body transports
location.assign(begun.authorization_url);

// On your callback page, at /auth/callback/google.
const query = new URLSearchParams(location.search);
history.replaceState(null, "", location.pathname); // take the code out of the address bar
const done = await fetch("/api/auth/oauth/complete", {
  method: "POST", credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    provider: "google", code: query.get("code"), state: query.get("state"), iss: query.get("iss") ?? undefined,
    binding: sessionStorage.getItem("oauth_binding") ?? undefined,
  }),
});
```

When the provider sends `error` instead of `code`, the user did not sign in at the provider. The page has nothing to post.

### The binding cookie

Under the cookie transports the cookie is named `__Host-behemoth_oauth_` followed by 16 characters derived from the state, so two sign-ins started in one browser keep a cookie each. It has these attributes:

- `HttpOnly`, `Path=/`, and no `Domain`. A browser sends it only to Behemoth's host.
- `Secure`, and the `SameSite` of the session cookie (`SessionConfig.CookieSameSite`). It reaches `POST /oauth/complete` on the requests that the session cookie reaches.
- `Max-Age` until the sign-in expires. A completed sign-in removes it.

With `SessionConfig.CookieInsecure` set, the cookie has no `Secure` attribute and its name has no `__Host-` prefix, which a browser accepts only with `Secure`.

## Routes

Paths are below the router's base path, `/api/auth` by default.

| Route | Body | Result |
| --- | --- | --- |
| `POST /sign-in/oauth` (`oauth.PathBegin`) | `provider`, and optionally `redirect_url`. Other fields go to handlers on `auth.oauth.beforeBegin`. | `200` with `{"authorization_url": "..."}`, and `binding` for a client without cookies. Sent with `Cache-Control: no-store`. |
| `POST /oauth/complete` (`oauth.PathComplete`) | `provider`, `code`, `state`, `iss` when the provider sent it, and `binding` for a client without cookies | `200` with `{"user": {...}, "redirect_url": "..."}`, or `{"status": "requires_second_factor", "redirect_url": "..."}` when a second factor is pending. The session token arrives by the configured transport. See [Sessions](sessions.md#the-sign-in-response). |

`redirect_url` is checked like the magic link's. It is a path on your own site, or an absolute URL whose origin is in `RouterConfig.TrustedOrigins`. See [The redirect URL](magiclink.md#the-redirect-url). Your page does the redirect.

### Error responses

| Route | When | Status | Code |
| --- | --- | --- | --- |
| both | the body is not valid JSON | `400` | `request_validation_error` |
| begin | `provider` is missing, not a string, or not a configured provider | `400` | `provider_invalid_input` |
| begin | `redirect_url` is not a string, or not allowed | `400` | `redirect_url_invalid_input` |
| complete | `provider`, `code`, or `state` is missing or not a string | `400` | `provider_invalid_input`, `code_invalid_input`, `state_invalid_input` |
| complete | `binding` or `iss` is not a string | `400` | `binding_invalid_input`, `iss_invalid_input` |
| complete | the state is unknown, expired, or already used; the binding value is missing or wrong; the provider is not the one the sign-in was started with; the provider refused the code; the ID token or the `iss` parameter failed a check | `401` | `invalid_oauth_callback` |
| complete | a user with the provider's email exists and has no account at this provider | `409` | `account_not_linked` |
| complete | the provider gave no usable email for a first sign-in | `403` | `email_not_provided` |
| both | too many requests | `429` with `Retry-After` | `rate_limited` |
| both | a hook handler rejected the request with a typed error | the error's status | the error's code |
| both | the provider failed | `500` | |

A refused callback that fails before the code is redeemed leaves the sign-in usable, so a request with a wrong binding value does not end the user's sign-in. From the redeem on, the state is used up, also when a later step refuses the sign-in. The user starts again.

## What a sign-in does

The plugin finds the user by the provider and the identity's `Subject`, never by email:

| The plugin finds | Result |
| --- | --- |
| an account for the provider and the subject | The account's user is signed in. Nothing of the provider's profile is written to the user. |
| no account, and no user with the identity's email | A user and the account are created, and the user is signed in. |
| no account, and a user with the identity's email | `409` `account_not_linked`. The user signs in the way they did before. |
| no account, and no usable email | `403` `email_not_provided`. |

A new user is built from the identity:

- **The email is normalized** (trimmed and lowercased), and `email_verified` is the identity's `EmailVerified`. With the email verification plugin installed, an unverified user gets a verification link.
- **The name** is `GivenName` and `FamilyName`, or `Name` as the first name when the provider gives no parts. Each is cut to 255 characters.
- **The picture** is kept only when it is an absolute `http` or `https` URL.
- **No token of the provider is stored.**

## Call the flows from code

Both flows are exported for a CLI, a test, or a transport other than HTTP.

```go
begun, err := plugin.Begin(ctx, oauth.BeginRequest{Provider: "google", RedirectURL: "/dashboard"})
// begun.AuthorizationURL, begun.State, begun.Binding, begun.ExpiresAt

signIn, err := plugin.Complete(ctx, oauth.CompleteRequest{
	Provider: "google", Code: code, State: state, Issuer: iss, Binding: begun.Binding,
})
// signIn.User, signIn.Session, signIn.RawToken, signIn.RedirectURL
```

The flows behave as follows:

- **You keep the binding value.** `Begin` returns it, and `Complete` needs it. Keep it with the client that started the sign-in, and never in a URL. A caller that stores it on its own server, looked up by the state, removes the protection it gives.
- **`Complete` delivers nothing.** It returns the raw session token. From a route of your own, hand `signIn.SignInResult` to `types.WriteSignIn`, which is what the plugin's route does.
- **Pass the context of the request being handled** when there is one, so the session records the client's address and handlers get the request.
- **Called before `Boot`,** both return a configuration error.

## Hooks

`Complete` fires the core sign-in points, and the sign-up points for a user it creates:

| Point | What the handler gets |
| --- | --- |
| `auth.signIn.before` | payload `method` (`"oauth"`) and `provider`. Veto only. The code, the state, and the binding value are not in the payload. |
| `auth.signIn.credentialsVerified` | `HookValueUserID`. Set `requireStepUp` to make the session pending. |
| `auth.signIn.after` | a `*types.SignInResult` with `Method` set to `"oauth"` |
| `auth.signIn.failed` | codes `invalid_oauth_state`, `oauth_provider_mismatch`, `oauth_binding_mismatch`, `oauth_exchange_refused`, `user_not_found`, `email_not_provided`, `account_not_linked`, `rejected_by_hook`. The metadata has the provider. |
| `auth.signUp.before` | payload `method`, `provider`, `email`, `email_verified`, `firstname`, `lastname`, and `image_url`. Veto only. |
| `auth.signUp.after` | the created `*models.User` |
| `auth.signUp.failed` | code `rejected_by_hook` |

A refused sign-up fires `auth.signUp.failed` and then `auth.signIn.failed`.

`hctx.Values[oauth.HookValueProvider]` holds the provider's id on every one of these points. When the subject is new and the identity has a usable email, `hctx.Values[hooks.HookValueEmail]` holds that email from the redeem on.

The plugin also declares three points around `Begin`:

| Point | Phase | What the handler gets |
| --- | --- | --- |
| `auth.oauth.beforeBegin` (`oauth.HookBeginBefore`) | before | payload `provider`, `redirect_url`, and the request's other fields. The returned payload becomes the input. |
| `auth.oauth.afterBegin` (`oauth.HookBeginAfter`) | after | a `*oauth.BeginResult` with the provider, the sign-in's id, and its expiry. Not the authorization URL, the state, or the binding value. |
| `auth.oauth.beginFailed` (`oauth.HookBeginFailed`) | failed | code `rejected_by_hook` |

None of the three is audited.

Starting and completing a sign-in also fire the token manager's points (`token.beforeIssue`, `token.afterIssue`, `token.consumed`, `token.failed`) with the kind `oauth_state`.

## Rate limits

The plugin declares two rules.

| Rule | Limits | Default |
| --- | --- | --- |
| `oauth.RuleBeginRoute` | requests to `POST /sign-in/oauth` per client address | 10 a minute |
| `oauth.RuleCompleteRoute` | requests to `POST /oauth/complete` per client address | 10 a minute |

## Limits

The plugin has these limits:

- **Three kinds built in.** Another provider is a `KindOIDC` one when it follows OpenID Connect, or a `Provider` you write. A Microsoft endpoint for several tenants names a placeholder as its issuer and does not work as `KindOIDC`. Use the endpoint of one tenant.
- **No linking.** A user who signed up with a password can't add a provider, and a first sign-in with that user's email is refused.
- **No provider tokens.** The plugin keeps none, so your application can't call the provider's API for the user afterwards.
- **No form posts.** A provider that posts the callback (`response_mode=form_post`) posts it to your application. Your endpoint has to accept the form and hand the code and the state to your page.
