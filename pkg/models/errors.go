package models

import (
	"errors"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"gorm.io/gorm"
)

var (
	// ErrUsernameExists indicates another user with the provided username exists
	ErrUsernameExists = errors.New("user with that username already exists")
	// ErrEmailExists indicates another user with the provided email exists
	ErrEmailExists = errors.New("user with that email already exists")
)

// ErrToStatus converts an error to a HTTP status code
func ErrToStatus(err error) int {
	switch {
	case errors.As(err, &validation.Errors{}), errors.Is(err, ErrUsernameExists), errors.Is(err, ErrEmailExists):
		return http.StatusBadRequest
	case errors.Is(err, gorm.ErrRecordNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
