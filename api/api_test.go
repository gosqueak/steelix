package api_test

import (
	"bytes"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gosqueak/jwt"
	"github.com/gosqueak/jwt/rs256"
	"github.com/gosqueak/steelix/api"
	"github.com/gosqueak/steelix/database"
)

const testDbFp = "testDb.sqlite"
const testKeyFp = "DEV.TEST.private"

const (
	testUsername = "testu"
	testPassword = "testp"
)

var privKey *rsa.PrivateKey

func TestMain(m *testing.M) {
	privKeyBytes, err := rs256.LoadKeyBytes(testKeyFp)
	if err != nil {
		panic(err)
	}

	privKey = rs256.ParsePrivateBytes(privKeyBytes)

	defer os.Remove(testDbFp)
	defer os.Remove(testKeyFp)
	m.Run()
}

func TestRegister(t *testing.T) {
	db := newDB()
	defer db.Close()
	_ = newServer(db, newIssuer(), newAudience())

	payload := map[string]string{
		"username": "",
		"password": "",
	}

	tests := []struct {
		info       string
		username   string
		password   string
		statuscode int
	}{
		{"add first user", "testuser", "testpassword", 200},
		{"add existant user", "testuser", "testpassword", 409},
		{"empty password", "testuser", "", 400},
		{"empty username", "", "testpassword", 400},
		{"empty body", "", "", 400},
	}

	var (
		req *http.Request
		rr  *httptest.ResponseRecorder
	)

	for _, test := range tests {
		payload["username"] = test.username
		payload["password"] = test.password
		body, _ := json.Marshal(payload)
		rr = httptest.NewRecorder()
		req = httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
		http.DefaultServeMux.ServeHTTP(rr, req)

		if rr.Code != test.statuscode {
			t.Errorf("%v (have %v want %v)", test.info, rr.Code, test.statuscode)
		}
	}
}

func TestLogin(t *testing.T) {
	db := newDB()
	defer db.Close()
	_ = newServer(db, newIssuer(), newAudience())

	payload := map[string]string{
		"username": "",
		"password": "",
	}

	tests := []struct {
		info       string
		username   string
		password   string
		statusCode int
	}{
		{"correct login", testUsername, testPassword, 200},
		{"wrong pwd", testUsername, "wrongpass", 401},
		{"nonexistant user", "nonexistant", "password", 401},
		{"empty username", "", "pass", 401},
		{"empty pwd, fake username", "user", "", 401},
		{"empty pwd, real username", testUsername, "", 401},
		{"empty login", "", "", 401},
	}

	var (
		req *http.Request
		rr  *httptest.ResponseRecorder
	)

	for _, test := range tests {
		payload["username"] = test.username
		payload["password"] = test.password
		body, _ := json.Marshal(payload)
		rr = httptest.NewRecorder()
		req = httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
		http.DefaultServeMux.ServeHTTP(rr, req)

		if rr.Code != test.statusCode {
			t.Errorf("%v (have %v want %v)", test.info, rr.Code, test.statusCode)
		}
	}
}

func TestHandleMakeAccessToken(t *testing.T) {
	db := newDB()
	defer db.Close()
	iss := newIssuer()
	aud := newAudience()
	_ = newServer(db, iss, aud)

	// fake issuer represents a MITM
	fakeIss := jwt.NewIssuer(rs256.GeneratePrivateKey(), "fakeissuer")

	// test various refresh tokens
	validToken := iss.StringifyJwt(iss.MintToken("testsubject", "AUTHAUD", time.Hour))
	expiredToken := iss.StringifyJwt(iss.MintToken("testsubject", "AUTHAUD", time.Nanosecond))
	wrongAudienceToken := iss.StringifyJwt(iss.MintToken("testsubject", "WRONG", time.Hour))
	emptyAudienceToken := iss.StringifyJwt(iss.MintToken("testsubject", "", time.Hour))
	invalidSignatureToken := fakeIss.StringifyJwt(fakeIss.MintToken("testsubject", "AUTHAUD", time.Hour))

	tests := []struct {
		info          string
		code          int
		refreshCookie *http.Cookie
	}{
		{"valid token", 200, &http.Cookie{Name: "refreshToken", Value: validToken}},
		{"empty token", 401, &http.Cookie{Name: "refreshToken", Value: ""}},
		{"invalid token string", 401, &http.Cookie{Name: "refreshToken", Value: "invalidstring"}},
		{"expired token", 401, &http.Cookie{Name: "refreshToken", Value: expiredToken}},
		{"wrong audience on token", 401, &http.Cookie{Name: "refreshToken", Value: wrongAudienceToken}},
		{"empty audience on token", 401, &http.Cookie{Name: "refreshToken", Value: emptyAudienceToken}},
		{"invalid signature", 401, &http.Cookie{Name: "refreshToken", Value: invalidSignatureToken}},
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", "/accesstokens", nil)
		rr := httptest.NewRecorder()
		req.AddCookie(test.refreshCookie)
		http.DefaultServeMux.ServeHTTP(rr, req)

		if rr.Code != test.code {
			t.Errorf("test: %v (got %v want %v)", test.info, rr.Code, test.code)
			continue
		}

		if test.code != 200 { // the next steps are only for 200 responses
			continue
		}

		var tokenStr string
		var foundCookie bool
		for _, cookie := range rr.Result().Cookies() {
			if cookie.Name == "accessToken" {
				tokenStr = cookie.Value
				foundCookie = true
				break
			}
		}
		if !foundCookie {
			t.Error(test.info, "Did not receive access token cookie")
			continue
		}
		if tokenStr == "" {
			t.Error(test.info, "access token is an empty string")
			continue
		}

		token, err := jwt.FromString(tokenStr)

		if err != nil {
			t.Error(test.info, err)
			continue
		}

		if !aud.IsValid(token) {
			t.Error(test.info, "the access token is invalid")
			continue
		}
	}
}

func TestHandleMakeApitoken(t *testing.T) {
	db := newDB()
	defer db.Close()
	iss := newIssuer()
	_ = newServer(db, iss, newAudience())

	fakeIss := jwt.NewIssuer(rs256.GeneratePrivateKey(), "fakeissuer")
	apiAudience := jwt.NewAudience(iss.PublicKey(), "alakazam")

	validToken := iss.StringifyJwt(iss.MintToken("testsubject", "AUTHAUD", time.Hour))
	invalidSignatureToken := fakeIss.StringifyJwt(fakeIss.MintToken("testsubject", "AUTHAUD", time.Hour))

	tests := []struct {
		info            string
		accessToken     string
		apiAudienceName string
		statusCode      int
	}{
		{"valid token and aud", validToken, "alakazam", 200},
		{"valid token, bad aud", validToken, "fakeaud", 401},
		{"valid token no aud", validToken, "", 400},
		{"invalid token, good aud", "badddatttaa", "alakazam", 401},
		{"empty token, good aud", "", "alakazam", 401},
		{"invalid signature on token", invalidSignatureToken, "alakazam", 401},
	}

	for _, test := range tests {
		path := "/apitokens?aud=" + test.apiAudienceName
		req := httptest.NewRequest("GET", path, nil)
		rr := httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: "accessToken", Value: test.accessToken})
		http.DefaultServeMux.ServeHTTP(rr, req)

		if rr.Code != test.statusCode {
			t.Errorf("test: %v (got %v want %v)", test.info, rr.Code, test.statusCode)
		}

		if rr.Code != 200 { // next steps are for 200 responses only
			continue
		}

		var tokenStr string
		var foundCookie bool
		for _, cookie := range rr.Result().Cookies() {
			if cookie.Name == test.apiAudienceName {
				tokenStr = cookie.Value
				foundCookie = true
				break
			}
		}
		if !foundCookie {
			t.Error(test.info, "Did not receive api token cookie")
			continue
		}
		if tokenStr == "" {
			t.Error(test.info, "api token is an empty string")
			continue
		}

		token, err := jwt.FromString(tokenStr)

		if err != nil {
			t.Error(test.info, err)
			continue
		}

		if !apiAudience.IsValid(token) {
			t.Error(test.info, "token can't be validated by API audience")
			continue
		}
	}
}

func newServer(db *sql.DB, iss jwt.Issuer, aud jwt.Audience) *api.Server {
	server := api.NewServer(
		db,
		"localhost:8081",
		"localhost:8080",
		iss,
		aud,
	)
	http.DefaultServeMux = http.NewServeMux()

	server.ConfigureRoutes()
	database.RegisterUser(db, testUsername, testPassword)

	return server
}

func newDB() *sql.DB {
	os.Remove(testDbFp)
	return database.Load(testDbFp)
}

func newIssuer() jwt.Issuer {
	return jwt.NewIssuer(
		privKey,
		"TESTISS",
	)
}

func newAudience() jwt.Audience {
	return jwt.NewAudience(
		&privKey.PublicKey,
		"AUTHAUD",
	)
}
