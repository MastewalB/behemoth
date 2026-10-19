package auth

import (
	"context"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/telemetry"
)

// DefaultAuthenticator is the Authenticator Boot builds. It resolves a
// session token through the session manager and applies the rolling
// expiration.
type DefaultAuthenticator struct {
	sessions core.SessionManager
	log      telemetry.Logger
}

// NewAuthenticator returns the authenticator of the session tokens sessions
// issued. tel may be nil.
func NewAuthenticator(sessions core.SessionManager, tel *telemetry.Telemetry) *DefaultAuthenticator {
	return &DefaultAuthenticator{sessions: sessions, log: telemetry.OrDefault(tel).Named("auth").Logger}
}

// Authenticate implements [core.Authenticator].
//
// An active session signs the caller in, after the rolling expiration: an
// extension that fails is not an error of the call, and the session is used
// as it was found. A session that waits for a second factor makes the caller
// anonymous with errs.CodeSessionPending, and the caller keeps the session
// for the second-factor flow.
func (a *DefaultAuthenticator) Authenticate(ctx context.Context, cred *core.Credential, peer identity.Peer) (identity.Caller, core.AuthOutcome) {
	const op = "Authenticate"
	if cred == nil {
		return identity.Anonymous(peer), core.AuthOutcome{}
	}
	if cred.Kind != core.CredentialSession {
		err := errs.NewSessionError(op, errs.CodeSessionInvalid, nil)
		return identity.Unauthenticated(peer, err, nil), core.AuthOutcome{}
	}

	session, err := a.sessions.Get(ctx, cred.Value)
	if err != nil {
		// To the lookup, a token that resolves to nothing is "not found",
		// which the router answers with 404. To a caller it is a credential
		// that belongs to no session.
		if errs.IsNotFound(err) {
			err = errs.NewSessionError(op, errs.CodeSessionInvalid, err)
		}
		if !errs.IsCategory(err, errs.CategorySession) {
			// The call goes on as anonymous, so a public flow never returns
			// this error; this line reports it.
			a.log.Warn(ctx, "session lookup failed; the call is anonymous", telemetry.ErrorFields(err))
		}
		return identity.Unauthenticated(peer, err, nil), core.AuthOutcome{Ended: sessionIsGone(err)}
	}
	if session.State == models.SessionPending {
		ref := sessionRef(session)
		err := errs.NewSessionError(op, errs.CodeSessionPending, nil)
		return identity.Unauthenticated(peer, err, &ref), core.AuthOutcome{}
	}

	var outcome core.AuthOutcome
	if extended, err := a.sessions.Touch(ctx, session); err == nil && extended != nil {
		session = extended
		ref := sessionRef(session)
		outcome.Extended = &ref
	}
	return identity.SignedIn(sessionRef(session), peer), outcome
}

// sessionRef returns the plain data of session that a caller carries.
func sessionRef(s *models.Session) identity.SessionRef {
	ref := identity.SessionRef{
		ID:        s.ID,
		UserID:    s.UserID,
		State:     string(s.State),
		ExpiresAt: s.ExpiresAt,
		FreshAt:   s.FreshAt,
	}
	if id, ok := s.ImpersonatorID.(string); ok {
		ref.ImpersonatorID = id
	}
	return ref
}

// sessionIsGone reports whether err says that a session has ended for good:
// its token belongs to no session, or the session is revoked or expired. A
// session that waits for a second factor is still live. Any other error says
// that the lookup failed, not what became of the session.
func sessionIsGone(err error) bool {
	return errs.IsCode(err, errs.CodeSessionInvalid) ||
		errs.IsCode(err, errs.CodeSessionRevoked) ||
		errs.IsCode(err, errs.CodeSessionExpired)
}

var _ core.Authenticator = (*DefaultAuthenticator)(nil)
