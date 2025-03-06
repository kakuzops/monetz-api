package user

import (
	"context"
	"regexp"

	"encore.app/user/security"
	"encore.dev/beta/errs"
	"encore.dev/pubsub"
	"encore.dev/storage/sqldb"
)

var db = sqldb.NewDatabase("user", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

// API defines the API for the user service
// encore: service
type API struct {
	Service UseCase
}

func initAPI() (*API, error) {
	return &API{Service: NewService(db)}, nil
}

// AuthEvent are the parameters to the AuthEvent
type AuthEvent struct {
	UserEmail string
}

// AuthEvents topic
var AuthEvents = pubsub.NewTopic[*AuthEvent]("auth", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
})

// AuthParams are the parameters to the Auth method
type AuthParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse is the response to the Auth method
type AuthResponse struct {
	Token string `json:"token"`
}

// Auth authenticates a user and returns a token
//
//encore:api public method=POST path=/v1/auth
func (a *API) Auth(ctx context.Context, p *AuthParams) (*AuthResponse, error) {
	// Construct a new error builder with errs.B()
	eb := errs.B().Meta("auth", p.Email)

	err := a.Service.ValidateUser(ctx, p.Email, p.Password)
	if err != nil {
		return nil, eb.Code(errs.Unauthenticated).Msg("invalid credentials").Err()
	}
	var response AuthResponse
	response.Token, err = security.NewToken(p.Email)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("internal error").Err()
	}
	_, err = AuthEvents.Publish(ctx, &AuthEvent{UserEmail: p.Email})
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("internal error").Err()
	}
	return &response, nil
}

// ValidateTokenParams are the parameters to the ValidateToken method
type ValidateTokenParams struct {
	Token string `json:"token"`
}

// ValidateTokenResponse is the response to the ValidateToken method
type ValidateTokenResponse struct {
	Email string `json:"email"`
}

// ValidateToken validates a token
//
//encore:api public method=POST path=/v1/validate-token
func (a *API) ValidateToken(ctx context.Context, p *ValidateTokenParams) (*ValidateTokenResponse, error) {
	// Construct a new error builder with errs.B()
	eb := errs.B().Meta("validate_token", p.Token)
	t, err := security.ParseToken(p.Token)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("internal error").Err()
	}
	tData, err := security.GetClaims(t)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("internal error").Err()
	}
	response := ValidateTokenResponse{
		Email: tData["email"].(string),
	}
	return &response, nil
}

// CreateUserParams are the parameters to the CreateUser method
type CreateUserParams struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// CreateUserResponse is the response to the CreateUser method
type CreateUserResponse struct {
	Token string `json:"token"`
}

// CreateUser creates a new user and returns a token
//
//encore:api public method=POST path=/v1/users
func (a *API) CreateUser(ctx context.Context, p *CreateUserParams) (*CreateUserResponse, error) {
	// Construct a new error builder with errs.B()
	eb := errs.B().Meta("create_user", p.Email)

	// Validate email format
	if !isValidEmail(p.Email) {
		return nil, eb.Code(errs.InvalidArgument).Msg("invalid email format").Err()
	}

	// Check if email already exists
	exists, err := a.Service.UserExists(ctx, p.Email)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("internal error").Err()
	}
	if exists {
		return nil, eb.Code(errs.AlreadyExists).Msg("email already exists").Err()
	}

	// Create user
	err = a.Service.CreateUser(ctx, p.Email, p.Password, p.FirstName, p.LastName)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("could not create user").Err()
	}

	// Generate token
	var response CreateUserResponse
	response.Token, err = security.NewToken(p.Email)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("internal error").Err()
	}

	// Publish auth event
	_, err = AuthEvents.Publish(ctx, &AuthEvent{UserEmail: p.Email})
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("internal error").Err()
	}

	return &response, nil
}

// isValidEmail validates the email format
func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}
