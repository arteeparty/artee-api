package datastore

import (
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"time"
)

// User is an account
type User struct {
	ID                string    `json:"-"`
	Name              string    `json:"first_name"`
	Phone             string    `json:"phone"`
	Email             string    `json:"email"`
	HashedPassword    []byte    `json:"-"`
	IdentityConfirmed bool      `json:"identity_confirmed"`
	ConfirmationToken string    `json:"-"`
	AuthTokenType     string    `json:"-"`
	Created           time.Time `json:"created"`
	Modified          time.Time `json:"modified"`
}

// IsCorrectPassword verifys a password is correct
func (u *User) IsCorrectPassword(plainTextPassword string) bool {
	return bcrypt.CompareHashAndPassword(u.HashedPassword, []byte(plainTextPassword)) == nil
}

func encryptToken(token string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
}

// SetPassword encrypts and sets a user's password
func (u *User) SetPassword(token string) error {
	b, err := encryptToken(token)
	if err != nil {
		return err
	}
	u.HashedPassword = b
	return nil
}

// UserService is for accessing users from with a datastore
type UserService struct {
	*sqlx.DB
}

// NewUserService creates a new UserService
func NewUserService(db *sqlx.DB) *UserService {
	return &UserService{DB: db}
}

// GetUser finds a user by id
func (u *UserService) GetUser(id string) (*User, error) {
	user := &User{}
	err := u.QueryRow("SELECT id, name, phone, email, password FROM users WHERE id=$1 LIMIT 1", id).Scan(&user.ID, &user.Name, &user.Phone, &user.Email, &user.HashedPassword)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByPhone finds a user by email
func (u *UserService) GetUserByPhone(phone string) (*User, error) {
	user := &User{}
	err := u.QueryRow("SELECT id, name, phone, email, password FROM users WHERE phone=$1 LIMIT 1", phone).Scan(&user.ID, &user.Name, &user.Phone, &user.Email, &user.HashedPassword)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// SetOTP sets a temprorary OTP code
func (u *UserService) SetOTP(phone, token string) error {
	securedToken, err := encryptToken(token)
	if err != nil {
		return err
	}
	_, err = u.Exec("UPDATE users SET password=$1 WHERE phone=$2", securedToken, phone)
	return err
}

// GetUserByConfirmationToken finds a user by confirmation token
func (u *UserService) GetUserByConfirmationToken(email, token string) (*User, error) {
	user := &User{}
	err := u.QueryRow("SELECT id, email, confirmation_token FROM users WHERE email=$1 AND confirmation_token=$2", email, token).Scan(&user.ID, &user.Email, &user.ConfirmationToken)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// InsertUser creates a new user
func (u *UserService) InsertUser(user *User) error {
	_, err := u.Exec("INSERT INTO users (name, phone, email, password) VALUES($1, $2, $3, $4)", user.Name, user.Phone, user.Email, user.HashedPassword)
	return err
}

// CheckEmail verifies a user with that email doesn't already exist
func (u *UserService) CheckEmail(email string) (bool, error) {
	var ok bool
	err := u.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email=$1)", email).Scan(&ok)
	return ok, err
}
