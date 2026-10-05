package main

import (
	"fmt"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	"github.com/MastewalB/behemoth/utils"
)

// invites are the codes this application accepts at sign-up, and who sent
// them. A real application would keep them in a table.
var invites = map[string]string{
	"WELCOME2026": "grace",
}

// Keys the application's handlers use in HookContext.Values.
const (
	valueInviter = "app.inviter" // string: who invited the new user
	valueTodo    = "app.todo"    // string: id of the todo created for the user
	valueSignIn  = "app.signin"  // bool: set by the sign-in before handler
)

// appHooks registers the application's own handlers (BootConfig.Hooks). The
// application needs no plugin for this; its handlers are ordered after the
// plugins' when nothing else decides.
//
// It implements invite codes on top of the email/password plugin without
// touching it:
//
//	auth.signUp.before     the code arrives as input, in the payload. The
//	                       handler checks it and keeps the inviter in Values.
//	data.user.afterCreate  a nested operation, so it sees a copy of those
//	                       Values. It creates the user's first todo in the
//	                       user's transaction, and leaves a note of its own.
//	data.user.created      same write, after commit: both notes are there.
//	auth.signUp.after      the sign-up again: the inviter is there, the
//	                       write's note is not.
//
// The caller of the flow never sets Values. It passes inviteCode as input,
// the same way from POST /api/auth/sign-up/email and from the signup
// command.
func appHooks(reg types.HookRegistry) error {
	if err := reg.OnBefore(hooks.HookSignUpBefore, func(hctx *types.HookContext, payload behemoth.M) (behemoth.M, error) {
		code, _ := payload["inviteCode"].(string)
		if code == "" {
			trace("app", hctx, "no invite code")
			return payload, nil
		}
		inviter, ok := invites[code]
		if !ok {
			trace("app", hctx, "unknown invite code, rejecting")
			// A typed error: the client gets a 400 with this message, and
			// auth.signUp.failed fires with code "rejectedByHook".
			return nil, behemotherr.NewInvalidInputError("app.invite", "invite", "this invite code is not valid", nil)
		}
		hctx.Values[valueInviter] = inviter
		trace("app", hctx, "invite accepted, inviter noted")
		return payload, nil
	}, nil); err != nil {
		return err
	}

	if err := reg.OnAfter(hooks.HookUserAfterCreate, func(hctx *types.HookContext, result any) error {
		inviter, invited := hctx.Values[valueInviter].(string)
		if !invited {
			trace("app", hctx, "not an invited user")
			return nil
		}
		user := result.(*models.User)
		todo := &Todo{ID: utils.GenerateUUID(), Title: fmt.Sprintf("Thank %s for inviting %s", inviter, user.Email)}
		// hctx.Tx.DB() is the adapter bound to the user's transaction: the
		// todo exists only if the user and its account do.
		if err := hctx.Tx.DB().Create(hctx.Ctx, todo); err != nil {
			return err
		}
		hctx.Values[valueTodo] = todo.ID
		trace("app", hctx, "todo created in the user's transaction")
		return nil
	}, nil); err != nil {
		return err
	}

	if err := reg.OnAfter(hooks.HookUserCreated, func(hctx *types.HookContext, _ any) error {
		trace("app", hctx, "user committed; the write's own note is still here")
		return nil
	}, nil); err != nil {
		return err
	}

	if err := reg.OnAfter(hooks.HookSignUpAfter, func(hctx *types.HookContext, _ any) error {
		_, leaked := hctx.Values[valueTodo]
		trace("app", hctx, fmt.Sprintf("sign-up done; sees the write's note: %v", leaked))
		return nil
	}, nil); err != nil {
		return err
	}

	// Sign-in creates a session, which is another nested operation: the
	// session manager's points start with a copy of the sign-in's Values.
	if err := reg.OnBefore(hooks.HookSignInBefore, func(hctx *types.HookContext, payload behemoth.M) (behemoth.M, error) {
		hctx.Values[valueSignIn] = true
		trace("app", hctx, "sign-in started")
		return payload, nil
	}, nil); err != nil {
		return err
	}
	return reg.OnBefore(hooks.HookSessionBeforeCreate, func(hctx *types.HookContext, payload behemoth.M) (behemoth.M, error) {
		// The session manager took the address from the request on the
		// context. From the signup command there is none, and it is empty.
		trace("app", hctx, fmt.Sprintf("session for ip=%q", payload[hooks.HookValueIPAddress]))
		return payload, nil
	}, nil)
}
