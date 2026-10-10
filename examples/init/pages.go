package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Paths of the application's pages the mailed links point to. They are the
// application's own routes, outside behemoth's base path.
const (
	pathMagicPage = "/auth/magic"
	pathResetPage = "/auth/reset"
)

// mountPages adds the two pages a mailed link opens.
//
// A link never points at behemoth. It points at a page of the application,
// which posts the link's token to behemoth. Mail scanners and link previews
// open the links in a message with a GET; if that were enough to sign in or
// to reset a password, the scanner would use the link up before the user
// got to it.
func mountPages(engine *gin.Engine) {
	page := func(html string) gin.HandlerFunc {
		return func(c *gin.Context) { c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html)) }
	}
	engine.GET(pathMagicPage, page(magicPage))
	engine.GET(pathResetPage, page(resetPage))
}

// magicPage finishes a magic link sign-in: the button posts the token to
// POST /api/auth/magic-link/verify. The example delivers session tokens in
// the Set-Auth-Token response header (types.TransportHeader), so the page
// reads it from there; with a cookie transport the browser would keep it.
const magicPage = `<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
<h1>Sign in</h1>
<button id="go">Sign me in</button>
<pre id="out"></pre>
<script>
const token = new URLSearchParams(location.search).get("token");
document.getElementById("go").onclick = async () => {
  const res = await fetch("/api/auth/magic-link/verify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({token}),
  });
  const body = await res.json();
  const session = res.headers.get("Set-Auth-Token");
  document.getElementById("out").textContent =
    res.status + " " + JSON.stringify(body, null, 2) + (session ? "\nsession token: " + session : "");
};
</script>
`

// resetPage finishes a password reset: it asks for the new password and
// posts it with the token to POST /api/auth/password-reset/confirm. A reset
// creates no session, so the user signs in with the new password afterwards.
const resetPage = `<!doctype html>
<meta charset="utf-8">
<title>Reset your password</title>
<h1>Reset your password</h1>
<form id="form">
  <input id="password" type="password" placeholder="New password" autocomplete="new-password" required>
  <button>Set password</button>
</form>
<pre id="out"></pre>
<script>
const token = new URLSearchParams(location.search).get("token");
document.getElementById("form").onsubmit = async (event) => {
  event.preventDefault();
  const res = await fetch("/api/auth/password-reset/confirm", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({token, password: document.getElementById("password").value}),
  });
  document.getElementById("out").textContent = res.status + " " + JSON.stringify(await res.json(), null, 2);
};
</script>
`
