package user

import (
	"context"
	"crypto/sha1"
	"fmt"

	"encore.dev/storage/sqldb"
	"github.com/google/uuid"
)

// UseCase is user logic interface
type UseCase interface {
	ValidateUser(ctx context.Context, email, password string) error
	ValidatePassword(ctx context.Context, u *User, password string) error
	CreateUser(ctx context.Context, email, password, firstName, lastName string) error
	UserExists(ctx context.Context, email string) (bool, error)
}

// Service is the service for the user package
type Service struct {
	DB *sqldb.Database
}

// NewService creates a new user service
func NewService(db *sqldb.Database) *Service {
	return &Service{DB: db}
}

// ValidateUser validates a user
func (s *Service) ValidateUser(ctx context.Context, email, password string) error {
	var u User
	err := s.DB.QueryRow(ctx, `
        select id, email, password, first_name, last_name from users where email = $1
    `, email).Scan(&u.ID, &u.Email, &u.Password, &u.FirstName, &u.LastName)
	if err != nil {
		return fmt.Errorf("invalid user %w", err)
	}
	err = s.ValidatePassword(ctx, &u, password)
	if err != nil {
		return fmt.Errorf("invalid user")
	}
	return nil
}

// ValidatePassword validates a password
func (s *Service) ValidatePassword(ctx context.Context, u *User, password string) error {
	h := sha1.New()
	h.Write([]byte(password))
	p := fmt.Sprintf("%x", h.Sum(nil))
	if p != u.Password {
		return fmt.Errorf("invalid password")
	}
	return nil
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, email, password, firstName, lastName string) error {
	h := sha1.New()
	h.Write([]byte(password))
	hashedPassword := fmt.Sprintf("%x", h.Sum(nil))

	// Generate a new UUID for the user ID
	userID := uuid.New().String()

	_, err := s.DB.Exec(ctx, `
        insert into users (id, email, password, first_name, last_name) values ($1, $2, $3, $4, $5)
    `, userID, email, hashedPassword, firstName, lastName)
	if err != nil {
		return fmt.Errorf("could not create user: %w", err)
	}
	return nil
}

// UserExists checks if a user with the given email already exists
func (s *Service) UserExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := s.DB.QueryRow(ctx, `
        select exists(select 1 from users where email = $1)
    `, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("could not check if user exists: %w", err)
	}
	return exists, nil
}
