package database_test

import (
	"os"
	"testing"

	"github.com/gosqueak/steelix/database"
)

const testDbPath = "test.db"

func TestMain(m *testing.M) {
	m.Run()
}

func TestRegisterUser(t *testing.T) {
	db := database.Load(testDbPath)
	defer db.Close()
	defer os.Remove(testDbPath)

	u := struct {
		name string
		pass string
	}{
		name: "test1",
		pass: "test1",
	}

	// test adding a new user
	err := database.RegisterUser(db, u.name, u.pass)

	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	ok, err := database.UserExists(db, u.name)

	if !ok {
		t.Error("expected user to exist in database")
	}
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// test empty username returns error
	u.name = ""
	err = database.RegisterUser(db, u.name, u.pass)
	if err == nil {
		t.Error("function should return an error when the username is empty")
	}

	// test empty password returns error
	u.name = "test2"
	u.pass = ""
	err = database.RegisterUser(db, u.name, u.pass)
	if err == nil {
		t.Error("function should return an error when the password is empty")
	}
}

func TestGetUser(t *testing.T) {
	db := database.Load(testDbPath)
	defer db.Close()
	defer os.Remove(testDbPath)

	u := struct{ name, pass string }{"test1", "test1"}

	// Test retrieving correct user after registration
	err := database.RegisterUser(db, u.name, u.pass)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	user, err := database.GetUser(db, database.DeriveUserId(u.name))
	if err != nil {
		t.Error(err)
	}

	if user.Uid != database.DeriveUserId(u.name) {
		t.Error("expected user id to match username")
	}

	// test trying to get a user that doesnt exist
	u.name = "fake"
	u.pass = "account"

	user, err = database.GetUser(db, database.DeriveUserId(u.name))
	if err == nil {
		t.Error("Expected error no such user")
	}

	// test that passing an empty userid returns ErrorNosuchUser
	user, err = database.GetUser(db, "")
	if err == nil {
		t.Error("should return a no such user error")
	}
}

func TestUserExists(t *testing.T) {
	db := database.Load(testDbPath)
	defer db.Close()
	defer os.Remove(testDbPath)

	// test checking for a existant user
	err := database.RegisterUser(db, "test1", "test1")
	if err != nil {
		t.Error(err)
	}

	ok, err := database.UserExists(db, "test1")
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.Error("Expected user to exist")
	}

	// test checking a non-existant user
	ok, err = database.UserExists(db, "fakename")

	if !(ok == false && err == nil) {
		t.Error("expected (false, nil) from call")
	}
}
