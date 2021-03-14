package models

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
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

var (
	tcdEmailRegex = regexp.MustCompile(`^\S+@tcd\.ie$`)
)

// UserMeta holds some GORM metadata about the User
type UserMeta struct {
	Created time.Time      `json:"created" gorm:"autoCreateTime;<-:create"`
	Updated time.Time      `json:"updated" gorm:"autoUpdateTime;<-:create"`
	Deleted gorm.DeletedAt `json:"-" gorm:"index;<-:create"`
}

// User represents a Netsoc member
type User struct {
	ID uint `json:"id" gorm:"primaryKey"`

	// User-modifiable
	Username  string  `json:"username" gorm:"uniqueIndex"`
	Email     string  `json:"email" gorm:"uniqueIndex"`
	Password  *string `json:"password,omitempty"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	SSHKey    *string `json:"ssh_key,omitempty"`

	// Only admin can set
	Verified *bool     `json:"verified" gorm:"not null"`
	Renewed  time.Time `json:"renewed"`
	IsAdmin  *bool     `json:"is_admin" gorm:"not null"`

	// Set only internally
	TokenVersion uint     `json:"-"`
	Meta         UserMeta `json:"meta" gorm:"embedded"`
}

// BeforeCreate is called by GORM before creating the User
func (u *User) BeforeCreate(tx *gorm.DB) error {
	// Make sure these fields are defaults
	u.ID = 0
	u.TokenVersion = 1

	// Will be set in the DB, but won't be updated in the object returned in the API
	f := false
	if u.Verified == nil {
		u.Verified = &f
	}
	if u.IsAdmin == nil {
		u.IsAdmin = &f
	}

	if err := validation.ValidateStruct(u,
		validation.Field(&u.Email, validation.Required, is.Email),
		validation.Field(&u.Username, validation.Required, is.DNSName),
		validation.Field(&u.Password, validation.When(u.Password != nil && *u.Password != "", validation.Length(8, 128))),

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

	if u.Password != nil && *u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*u.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		h := string(hash)
		u.Password = &h
	}

	return nil
}

// BeforeUpdate is called by GORM before updating the User
func (u *User) BeforeUpdate(tx *gorm.DB) error {
	patch, ok := tx.Statement.Dest.(User)
	if !ok {
		return ErrInvalidUpdate
	}

	if tx.Statement.Changed("ID", "TokenVersion") {
		return ErrInternalField
	}

	if err := validation.ValidateStruct(&patch,
		validation.Field(&patch.Email, is.Email),
		validation.Field(&patch.Username, is.DNSName),
		validation.Field(&patch.Password, validation.When(*u.Password != "", validation.Length(8, 128))),
	); err != nil {
		return err
	}

	shouldRoll := false
	if tx.Statement.Changed("Verified") || tx.Statement.Changed("IsAdmin") {
		shouldRoll = true
	}

	if tx.Statement.Changed("Username") {
		if err := tx.First(&User{}, "username = ?", patch.Username).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("failed to check existing users: %w", err)
			}
		} else {
			return ErrUsernameExists
		}
	}

	if tx.Statement.Changed("Email") {
		if err := tx.First(&User{}, "email = ?", patch.Email).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("failed to check existing users: %w", err)
			}
		} else {
			return ErrEmailExists
		}

		shouldRoll = true

		f := false
		u.Verified = &f
		tx.Statement.SetColumn("Verified", false)
	}

	if tx.Statement.Changed("Password") {
		if patch.Password != nil && *patch.Password != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(*patch.Password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash password: %w", err)
			}

			h := string(hash)
			u.Password = &h
			tx.Statement.SetColumn("Password", u.Password)
		}

		shouldRoll = true
	}

	if shouldRoll {
		u.TokenVersion++
		tx.Statement.SetColumn("TokenVersion", u.TokenVersion)
	}

	return nil
}

// CheckPassword validates a password against the stored hash
func (u *User) CheckPassword(password string) error {
	if u.Password == nil || *u.Password == "" {
		return ErrLoginDisabled
	}

	return bcrypt.CompareHashAndPassword([]byte(*u.Password), []byte(password))
}

// NonAdminSaveOK returns true if a partial User (patch) can be saved with a non-admin account
func (u *User) NonAdminSaveOK(reservedUsernames []string) error {
	if (u.Email != "" && !tcdEmailRegex.MatchString(u.Email)) || u.Verified != nil || !u.Renewed.IsZero() || u.IsAdmin != nil {
		return ErrAdminRequired
	}

	if u.Username != "" {
		lower := strings.ToLower(u.Username)
		for _, reserved := range reservedUsernames {
			if lower == reserved {
				return ErrReservedUsername
			}
		}
	}

	return nil
}

// Clean scrubs fields which should not be visible in a returned object
func (u *User) Clean() {
	u.Password = nil
}

// ValidAdmin returns whether or not a user is a "valid admin" (IsAdmin and not
// expired)
func (u *User) ValidAdmin(claims *UserClaims) bool {
	return *u.IsAdmin && claims.ExpiresAt.After(time.Now())
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
		IsAdmin: *u.IsAdmin,
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
