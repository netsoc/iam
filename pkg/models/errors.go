package models

import (
	"errors"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	// ErrUsernameExists indicates another user with the provided username exists
	ErrUsernameExists = errors.New("user with that username already exists")
	// ErrEmailExists indicates another user with the provided email exists
	ErrEmailExists = errors.New("user with that email already exists")
	// ErrLoginDisabled indicates login is disabled for this user
	ErrLoginDisabled = errors.New("login is disabled for this user")
	// ErrTokenRequired indicates a JWT is required for this endpoint
	ErrTokenRequired = errors.New("a valid token is required for this endpoint")
	// ErrAdminRequired indicates that an admin user is required
	ErrAdminRequired = errors.New("only admin users can make use of this endpoint")
	// ErrTokenExpired indicates that a user's token has expired
	ErrTokenExpired = errors.New("your token has expired")
)

// ErrToStatus converts an error to a HTTP status code
func ErrToStatus(err error) int {
	switch {
	case errors.As(err, &validation.Errors{}), errors.Is(err, ErrLoginDisabled):
		return http.StatusBadRequest
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword), errors.Is(err, ErrTokenRequired),
		errors.Is(err, ErrTokenExpired):
		return http.StatusUnauthorized
	case errors.Is(err, ErrAdminRequired):
		return http.StatusForbidden
	case errors.Is(err, gorm.ErrRecordNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrUsernameExists), errors.Is(err, ErrEmailExists):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
