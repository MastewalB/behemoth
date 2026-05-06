package behemoth

import "context"

type AuthTransportManager interface {
	Create(ctx context.Context, userID string) (string, error)
	Validate(ctx context.Context, tokenOrID string) (any, error)
	Revoke(ctx context.Context, tokenOrID string) error
}
