package models

import (
	"errors"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	// ErrUserNotFound indicates the user attempted to perform an API call with a username that does not exist
	ErrUserNotFound = errors.New("user does not exist")
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
	// ErrIncorrectPassword indicates the provide password was incorrect
	ErrIncorrectPassword = errors.New("incorrect password")
	// ErrUnverified indicates the user's email is not verified
	ErrUnverified = errors.New("email address is not verified")
	// ErrVerified indicates the user's email is already verified
	ErrVerified = errors.New("email address is already verified")
	// ErrOtherVerification indicates the user attempted to verify another user
	ErrOtherVerification = errors.New("can only verify own account")
	// ErrOtherReset indicates the user attempted to reset the password of another user
	ErrOtherReset = errors.New("can only reset password for own account")
	// ErrReservedUsername indicates a user attempted to use a reserved username
	ErrReservedUsername = errors.New("username is reserved, contact support if this username previously belonged to you")
	// ErrPasswordRequired indicates a user attempt to reset their password without providing a password
	ErrPasswordRequired = errors.New("password is required")
)

// ErrToStatus converts an error to a HTTP status code
func ErrToStatus(err error) int {
	switch {
	case errors.As(err, &validation.Errors{}), errors.Is(err, ErrLoginDisabled), errors.Is(err, ErrOtherVerification),
		errors.Is(err, ErrVerified), errors.Is(err, ErrOtherReset), errors.Is(err, ErrPasswordRequired):
		return http.StatusBadRequest
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword), errors.Is(err, ErrTokenRequired),
		errors.Is(err, ErrTokenExpired), errors.Is(err, ErrIncorrectPassword), errors.Is(err, ErrUnverified):
		return http.StatusUnauthorized
	case errors.Is(err, ErrAdminRequired), errors.Is(err, ErrReservedUsername):
		return http.StatusForbidden
	case errors.Is(err, gorm.ErrRecordNotFound), errors.Is(err, ErrUserNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrUsernameExists), errors.Is(err, ErrEmailExists):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
