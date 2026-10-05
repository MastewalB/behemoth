package main

import (
	"context"
	"fmt"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
)

// signup creates a user and signs them in without an HTTP request, by
// calling the email/password plugin's exported flows. The same hook
// handlers run as for the routes; they see HookContext.Request == nil, and
// the session records no IP address or user agent.
//
// invite is passed as input, exactly like the route's "inviteCode" field.
// The application's handler on auth.signUp.before picks it up from the
// payload (hooks.go).
func signup(ctx context.Context, email, password, invite string) error {
	_, ep, sqlDB, err := boot(ctx, nil)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	input := behemoth.M{"email": email, "password": password}
	if invite != "" {
		input["inviteCode"] = invite
	}
	user, err := ep.SignUp(ctx, input)
	if err != nil {
		return fmt.Errorf("sign-up: %w", err)
	}
	fmt.Printf("created user %s (%s)\n", user.ID, user.Email)

	result, err := ep.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: email, Password: password})
	if err != nil {
		return fmt.Errorf("sign-in: %w", err)
	}
	fmt.Printf("signed in: session %s, state %s, ip %q\n", result.Session.ID, result.Session.State, result.Session.IPAddress)
	return nil
}
