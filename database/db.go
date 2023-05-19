package database

import (
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

const (
	UserUidLength = 20
	HashKeyLength = 32
)

var ErrUserExists errorUserExists
var ErrNoSuchUser errorNoSuchUser
var ErrBadData errorBadData

// models "users" table in DB
type User struct {
	Uid          string
	HashedPwdB64 string
	HashSaltB64  string
}

// Generate a databse model for a new user
func NewUser(username, password string, salt []byte) User {
	// TODO there is a bug somewhere around here causing password login to break
	//   after creating a new user account, the user cannot login with their password.
	return User{
		Uid:          DeriveUserId(username),
		HashedPwdB64: b64EncodeString(HashString(password, salt)),
		HashSaltB64:  b64EncodeString(salt),
	}
}

func GetUser(db *sql.DB, userId string) (User, error) {
	stmt := "SELECT * FROM user WHERE id=?"

	var u User
	err := db.QueryRow(stmt, userId).Scan(
		&u.Uid,
		&u.HashedPwdB64,
		&u.HashSaltB64,
	)

	ok, err := queryHasResults(err)

	if !ok && err == nil {
		return u, ErrNoSuchUser
	}

	return u, err
}

// get a reproducible b64 string by hashing with no salt
func DeriveUserId(username string) string {
	noSalt := []byte{}
	return b64EncodeString(HashString(username, noSalt))
}

// return whether a id corresponding to the username exists
func UserExists(db *sql.DB, username string) (bool, error) {
	stmt := "SELECT id FROM user WHERE id=?"
	row := db.QueryRow(stmt, DeriveUserId(username))

	err := row.Scan(new(string))

	return queryHasResults(err)
}

func RegisterUser(db *sql.DB, username, password string) error {
	if username == "" || password == "" {
		return ErrBadData
	}

	// err if user exists already
	ok, err := UserExists(db, username)
	if ok {
		return errorUserExists{username}
	}

	if err != nil {
		return err
	}

	// random salt for hashing password
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// persisted data
	u := NewUser(username, password, salt)

	stmt := `
		INSERT INTO user (id, hashedPw, hashSalt) VALUES(?, ?, ?);
	`

	if _, err := db.Exec(stmt, u.Uid, u.HashedPwdB64, u.HashSaltB64); err != nil {
		return err
	}

	return nil
}

func HashString(s string, salt []byte) []byte {
	return pbkdf2.Key([]byte(s), salt, 4096, HashKeyLength, sha1.New)
}

// Load the database if it exists, or create a new one at the given path.
func Load(fp string) *sql.DB {
	d, err := sql.Open("sqlite3", fp)
	if err != nil {
		panic(err)
	}

	_, err = d.Exec(`
		CREATE TABLE IF NOT EXISTS user (
			id TEXT PRIMARY KEY,
			hashedPw TEXT NOT NULL,
			hashSalt TEXT NOT NULL
		);
	`)

	if err != nil {
		panic(err)
	}

	return d
}

// (false, nil) if the err is sql.ErrNowRows; or (false, err) for any other error.
func queryHasResults(e error) (ok bool, err error) {
	ok = e == nil
	if e == sql.ErrNoRows {
		err = nil
	}
	return ok, err
}

// convert bytes to a base64 string
func b64EncodeString(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

type errorUserExists struct{ Username string }

func (e errorUserExists) Error() string {
	return fmt.Sprintf("username: %s already exists", e.Username)
}

type errorNoSuchUser struct{ Username string }

func (e errorNoSuchUser) Error() string {
	return fmt.Sprintf("no such username: %s", e.Username)
}

type errorBadData struct{ info string }

func (e errorBadData) Error() string {
	return e.info
}
