package behemoth

import "context"

type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeCookie TokenType = "cookie"
)

type AuthTransportManager interface {
	Create(ctx context.Context, userID string) (string, error)
	Verify(ctx context.Context, tokenOrID string) (any, error)
	Revoke(ctx context.Context, tokenOrID string) error
	TokenType() TokenType
}
