package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/MastewalB/behemoth/types"
)

// appURL is where the application's own pages are served, without a
// trailing slash. The links behemoth mails point at pages under it
// (pages.go). APP_URL defaults to http://localhost:8080.
func appURL() string {
	if u := os.Getenv("APP_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8080"
}

// printMail is the example's mail sender (BootConfig.Mail.Sender). Behemoth
// sends nothing itself: every plugin that has a message hands it here, and
// msg.Kind says which one it is. A real sender picks a template by the kind
// and gives the message to SMTP, a provider's API or a queue.
//
// This one prints the message, so the link can be copied from the server's
// output. The link holds the raw token, which is a credential: a real
// application never logs it.
func printMail(_ context.Context, msg types.MailMessage) error {
	switch msg.Kind {
	case types.MailMagicLink:
		log.Printf("[mail] to=%s  Your sign-in link (until %s): %s", msg.To, msg.ExpiresAt.Format("15:04:05"), msg.URL)
	case types.MailPasswordReset:
		log.Printf("[mail] to=%s  Reset your password (until %s): %s", msg.To, msg.ExpiresAt.Format("15:04:05"), msg.URL)
	case types.MailPasswordChanged:
		// A notice without a link, sent after a reset went through.
		log.Printf("[mail] to=%s  Your password was changed. If this was not you, contact support.", msg.To)
	default:
		// An error for a kind without a template makes a missing one
		// visible: the mailer logs it and counts it.
		return fmt.Errorf("no template for mail kind %q", msg.Kind)
	}
	return nil
}
