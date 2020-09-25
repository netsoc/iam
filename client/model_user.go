/*
 * Netsoc IAM
 *
 * API for managing and authenticating Netsoc users. 
 *
 * API version: 1.0.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package iam
import (
	"time"
)
// User struct for User
type User struct {
	// Unique database identifier, not modifiable.
	Id int32 `json:"id"`
	// Unique username (must be a valid DNS name)
	Username string `json:"username"`
	// Unique email address (must be `@tcd.ie`)
	Email string `json:"email"`
	// Stored internally as a bcrypt hash. If unset, login will be disabled. 
	Password string `json:"password,omitempty"`
	FirstName string `json:"first_name"`
	LastName string `json:"last_name"`
	// Indicates if the user is an admin. Only modifiable by an admin.
	IsAdmin bool `json:"is_admin,omitempty"`
	// Date and time when the user's membership was last renewed. Only modifiable by an admin. 
	Renewed time.Time `json:"renewed,omitempty"`
	Meta UserMeta `json:"meta,omitempty"`
}
