package models

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go/v4"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SelfUser is a special username meaning the currently authenticated user
const SelfUser = "self"

var (
	// AudAuth is the JWT audience for regular authentication tokens
	AudAuth = "auth"
	// AudVerification is the JWT audience for email verification tokens
	AudVerification = "verification"
	// AudPasswordReset is the JWT audience for password reset tokens
	AudPasswordReset = "password_reset"
)

var bcryptRegex = regexp.MustCompile(`^\$2[ayb]\$.{56}$`)

// UserMeta holds some GORM metadata about the User
type UserMeta struct {
	Created time.Time      `json:"created" gorm:"autoCreateTime"`
	Updated time.Time      `json:"updated" gorm:"autoUpdateTime"`
	Deleted gorm.DeletedAt `json:"-" gorm:"index"`
}

// User represents a Netsoc member
type User struct {
	ID uint `json:"id" gorm:"primaryKey"`

	// User-modifiable
	Username  string `json:"username" gorm:"uniqueIndex"`
	Email     string `json:"email" gorm:"uniqueIndex"`
	Password  string `json:"password,omitempty"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`

	// Only admin can set
	Verified bool      `json:"verified"`
	Renewed  time.Time `json:"renewed"`
	IsAdmin  bool      `json:"is_admin"`

	// Set only internally
	TokenVersion uint     `json:"-"`
	Meta         UserMeta `json:"meta" gorm:"embedded"`
}

// SaveRequiresAdmin returns true if a partial User (patch) requires admin to save
func (u *User) SaveRequiresAdmin() bool {
	return u.Verified || !u.Renewed.IsZero() || u.IsAdmin
}

// Clean scrubs fields which should not be visible in a returned object
func (u *User) Clean() {
	u.Password = ""
}

// BeforeCreate is called by GORM before creating the User
func (u *User) BeforeCreate(tx *gorm.DB) error {
	// Make sure these fields are defaults
	u.ID = 0
	u.TokenVersion = 1
	u.Meta = UserMeta{}

	if err := validation.ValidateStruct(u,
		validation.Field(&u.Email, validation.Required, is.Email,
			validation.Match(regexp.MustCompile(`^\S+@tcd\.ie$`)).Error("only @tcd.ie emails are allowed")),
		validation.Field(&u.Username, validation.Required, is.DNSName),
		validation.Field(&u.Password, validation.When(u.Password != "", validation.Length(8, 128))),

		validation.Field(&u.FirstName, validation.Required),
		validation.Field(&u.LastName, validation.Required),
	); err != nil {
		return err
	}

	if err := tx.First(&User{}, "username = ?", u.Username).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to check existing users: %w", err)
		}
	} else {
		return ErrUsernameExists
	}
	if err := tx.First(&User{}, "email = ?", u.Email).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to check existing users: %w", err)
		}
	} else {
		return ErrEmailExists
	}

	if u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		u.Password = string(hash)
	}
	return nil
}

// BeforeUpdate is called by GORM before updating the User
func (u *User) BeforeUpdate(tx *gorm.DB) error {
	// Make sure these fields are defaults
	u.ID = 0
	u.Meta = UserMeta{}

	if err := validation.ValidateStruct(u,
		validation.Field(&u.Email, is.Email,
			validation.Match(regexp.MustCompile(`^\S+@tcd\.ie$`)).Error("only @tcd.ie emails are allowed")),
		validation.Field(&u.Username, is.DNSName),
		validation.Field(&u.Password, validation.When(u.Password != "", validation.Length(8, 128))),
	); err != nil {
		return err
	}

	if u.Username != "" {
		if err := tx.First(&User{}, "username = ?", u.Username).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("failed to check existing users: %w", err)
			}
		} else {
			return ErrUsernameExists
		}
	}
	if u.Email != "" {
		if err := tx.First(&User{}, "email = ?", u.Email).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("failed to check existing users: %w", err)
			}
		} else {
			return ErrEmailExists
		}

		// Verified has to be reset elsewhere since this is a patch
	}

	if u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		// Token version has to be rolled elsewhere since we only have the patch version (aka 0) here
		u.Password = string(hash)
	}
	return nil
}

// CheckPassword validates a password against the stored hash
func (u *User) CheckPassword(password string) error {
	if u.Password == "" {
		return ErrLoginDisabled
	}

	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
}

// UserClaims represents claims in an auth JWT
type UserClaims struct {
	jwt.StandardClaims
	IsAdmin bool `json:"is_admin"`
	Version uint `json:"version"`
}

// GenerateToken generates a JWT for the user
func (u *User) GenerateToken(key []byte, issuer string, expiry time.Time) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   strconv.Itoa(int(u.ID)),
			IssuedAt:  jwt.Now(),
			NotBefore: jwt.Now(),
			ExpiresAt: jwt.At(expiry),
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{AudAuth},
		},
		Version: u.TokenVersion,
		IsAdmin: u.IsAdmin,
	})

	return t.SignedString(key)
}

// EmailClaims represents claims in an emailed JWT
type EmailClaims struct {
	jwt.StandardClaims
	Version uint `json:"version"`
}

// GenerateEmailToken generates a JWT for sending by email the user
func (u *User) GenerateEmailToken(key []byte, issuer, audience string, validity time.Duration) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, EmailClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   strconv.Itoa(int(u.ID)),
			IssuedAt:  jwt.Now(),
			NotBefore: jwt.Now(),
			ExpiresAt: jwt.At(time.Now().Add(validity)),
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
		},
		Version: u.TokenVersion,
	})

	return t.SignedString(key)
}
