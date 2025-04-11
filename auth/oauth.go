package auth

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/utils"
	"github.com/go-chi/chi/v5"
)

// OAuthAuth manages OAuth-based authentication for multiple providers.
// It supports generic user types and handles authentication flows for providers like Google and Facebook.
type OAuthAuth[T behemoth.User] struct {
	providers      map[string]behemoth.Provider
	jwtSvc         *JWTService
	useDefaultUser bool
	db             behemoth.Database[T]
}

func NewOAuthAuth[T behemoth.User](
	oAuthProviders []behemoth.Provider,
	jwtSvc *JWTService,
	useDefaultUser bool,
	user behemoth.User,
	db behemoth.Database[T],
) *OAuthAuth[T] {

	providers := make(map[string]behemoth.Provider)
	for _, provider := range oAuthProviders {
		providers[provider.Name()] = provider
	}

	return &OAuthAuth[T]{
		providers:      providers,
		db:             db,
		jwtSvc:         jwtSvc,
		useDefaultUser: useDefaultUser,
	}
}

// Authenticate performs OAuth authentication for the specified provider using the given credentials.
// It exchanges the OAuth code for a token, fetches user info, and saves the user to the database.
// Returns the authenticated user or an error if authentication fails.
func (o *OAuthAuth[T]) Authenticate(providerName string, creds any) (behemoth.User, error) {

	provider, exists := o.providers[providerName]
	if !exists {
		return nil, errors.New("provider not found: " + providerName)
	}

	code, ok := creds.(string) // OAuth code from redirect
	if !ok {
		return nil, errors.New("invalid OAuth code")
	}

	config := provider.GetConfig()
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}
	// Fetch user info (provider-specific, e.g., Google API)
	client := config.Client(context.Background(), token)
	userInfo, err := provider.FetchUserInfo(client, context.Background(), token)
	if err != nil {
		return nil, errors.New("failed to get user info: " + err.Error())
	}
	log.Println(userInfo)

	// Create or update user
	var user *models.User
	if o.useDefaultUser {
		user = &models.User{}
		user.FromUserInfo(userInfo)

		if user, err = o.db.SaveUser(user); err != nil {
			return nil, errors.New("failed to save user: " + err.Error())
		}
	}

	return user, nil
}

func (o *OAuthAuth[T]) Register(providerName string, creds any) (behemoth.User, error) {
	return o.Authenticate(providerName, creds) // OAuth often combines auth/register
}

func (o *OAuthAuth[T]) AuthURL(req *http.Request, state string) (string, error) {
	providerName, err := getProviderName(req)
	if err != nil {
		return "", err
	}
	provider, exists := o.providers[providerName]
	if !exists {
		return "", errors.New("unknown OAuth provider: " + providerName)
	}
	if state == "" {
		state = utils.GenerateState()
	}
	return provider.GetConfig().AuthCodeURL(state), nil
}

func getProviderName(req *http.Request) (string, error) {
	// from the url param "provider"
	if p := req.URL.Query().Get("provider"); p != "" {
		return p, nil
	}

	// from the url param ":provider"
	if p := req.URL.Query().Get(":provider"); p != "" {
		return p, nil
	}

	if p := chi.URLParam(req, "provider"); p != "" {
		return p, nil
	}

	//  try to get it from the go-context's value of "provider" key
	if p, ok := req.Context().Value("provider").(string); ok {
		return p, nil
	}

	return "", errors.New("no provider selected")
}
