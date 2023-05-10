package api_test

import (
	"bytes"
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

var server *api.Server
var db *sql.DB
var aud jwt.Audience
var iss jwt.Issuer

func TestMain(m *testing.M) {
	keyBytes, err := rs256.LoadKeyBytes(testKeyFp)
	if err != nil {
		panic(err)
	}

	iss = jwt.NewIssuer(
		rs256.ParsePrivateBytes(keyBytes),
		"TESTISS",
	)

	aud = jwt.NewAudience(
		iss.PublicKey(),
		"AUTHAUD",
	)
	db = database.Load(testDbFp)
	server = api.NewServer(":8080", db, iss, aud)
	server.ConfigureRoutes()

	defer db.Close()
	defer os.Remove(testDbFp)
	defer os.Remove(testKeyFp)
	m.Run()
}

func TestRegister(t *testing.T) {
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
		{"correct login", "testuser", "testpassword", 200},
		{"wrong pwd", "testuser", "wrongpassword", 401},
		{"nonexistant user", "nonexistant", "password", 401},
		{"empty username", "", "pass", 401},
		{"empty pwd, fake username", "user", "", 401},
		{"empty pwd, real username", "testuser", "", 401},
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
	fakeIss := jwt.NewIssuer(rs256.GeneratePrivateKey(), "fakeissuer")
	apiAudience := jwt.NewAudience(iss.PublicKey(), "MSGSERVICE")

	validToken := iss.StringifyJwt(iss.MintToken("testsubject", "AUTHAUD", time.Hour))
	invalidSignatureToken := fakeIss.StringifyJwt(fakeIss.MintToken("testsubject", "AUTHAUD", time.Hour))

	tests := []struct {
		info            string
		accessToken     string
		apiAudienceName string
		statusCode      int
	}{
		{"valid token and aud", validToken, "MSGSERVICE", 200},
		{"valid token, bad aud", validToken, "fakeaud", 401},
		{"valid token no aud", validToken, "", 400},
		{"invalid token, good aud", "badddatttaa", "MSGSERVICE", 401},
		{"empty token, good aud", "", "MSGSERVICE", 401},
		{"invalid signature on token", invalidSignatureToken, "MSGSERVICE", 401},
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
