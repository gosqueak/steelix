package api

import (
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	kit "github.com/gosqueak/apikit"
	middlew "github.com/gosqueak/apikit/middleware"
	"github.com/gosqueak/jwt"
	dbkit "github.com/gosqueak/steelix/database"
)

const (
	RefreshTokenTTL = time.Hour * 24 * 7
	ApiTokenTTL     = time.Minute * 4
	AccessTokenTTL  = time.Minute * 20
)

var validAudNames []string = []string{"alakazam", "klefki"}

type Server struct {
	db           *sql.DB
	addr         string
	jwtIssuer    jwt.Issuer
	jwtAudience  jwt.Audience
	clientOrigin string
}

func NewServer(db *sql.DB, addr, clientOrigin string, iss jwt.Issuer, aud jwt.Audience) *Server {
	return &Server{
		db:           db,
		addr:         addr,
		jwtIssuer:    iss,
		jwtAudience:  aud,
		clientOrigin: clientOrigin,
	}
}

func (s *Server) ConfigureRoutes() {
	http.HandleFunc("/jwtkeypub", middlew.Log(s.handleGetJwtPublicKey))
	http.HandleFunc("/register", middlew.Log(s.handleRegisterUser))
	http.HandleFunc("/logout", middlew.Log(s.handleLogout))
	http.HandleFunc("/login", middlew.Log(s.handlePasswordLogin))
	http.HandleFunc("/apitokens", middlew.Log(middlew.CheckToken(kit.CookieNameAccessToken, s.jwtAudience, s.handleMakeApiTokens)))
	http.HandleFunc("/accesstokens", middlew.Log(middlew.CheckToken(kit.CookieNameRefreshToken, s.jwtAudience, s.handleMakeAccessTokens)))
}

func (s *Server) Run() {
	s.ConfigureRoutes()
	// start serving
	log.Fatal(http.ListenAndServe(s.addr, nil))
}

func (s *Server) handleGetJwtPublicKey(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write(x509.MarshalPKCS1PublicKey(s.jwtIssuer.PublicKey()))
	if err != nil {
		kit.Error(w, "", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		kit.Error(w, "could not decode JSON body", http.StatusBadRequest)
		return
	}

	err = dbkit.RegisterUser(s.db, body.Username, body.Password)
	if err != nil {
		if errors.As(err, &dbkit.ErrUserExists) {
			kit.Error(w, err.Error(), http.StatusConflict)
		} else if errors.As(err, &dbkit.ErrBadData) {
			kit.Error(w, "", http.StatusBadRequest)
		} else {
			kit.Error(w, "", http.StatusInternalServerError)
		}
	}
}

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var respBody struct {
		UserID string `json:"userID"`
	}

	// read body and validate
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		kit.Error(w, "could not decode JSON body", http.StatusBadRequest)
		return
	}

	// return a 401 if the username or password is wrong
	ok, err := verifyPassword(s.db, reqBody.Username, reqBody.Password)

	if !ok || errors.As(err, &dbkit.ErrNoSuchUser) {
		kit.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		kit.Error(w, "", http.StatusInternalServerError)
		return
	}

	userId := dbkit.DeriveUserId(reqBody.Username)

	// Set a new refresh token
	refreshToken := s.jwtIssuer.StringifyJwt(
		s.jwtIssuer.MintToken(userId, s.jwtIssuer.Name, RefreshTokenTTL),
	)
	kit.SetHttpOnlyCookie(w, s.clientOrigin, kit.CookieNameRefreshToken, refreshToken, int(RefreshTokenTTL.Seconds()))

	// set a new access token
	accessToken := s.jwtIssuer.StringifyJwt(
		s.jwtIssuer.MintToken(userId, s.jwtAudience.Name, AccessTokenTTL),
	)
	kit.SetHttpOnlyCookie(w, s.clientOrigin, kit.CookieNameAccessToken, accessToken, int(AccessTokenTTL.Seconds()))

	respBody.UserID = userId

	if err = json.NewEncoder(w).Encode(respBody); err != nil {
		kit.Error(w, "", http.StatusInternalServerError)
	}
}

func (s *Server) handleMakeAccessTokens(w http.ResponseWriter, r *http.Request) {
	token := r.Context().Value(kit.CookieNameRefreshToken).(jwt.Jwt)

	accessToken := s.jwtIssuer.StringifyJwt(
		s.jwtIssuer.MintToken(
			token.Body.Subject,
			s.jwtAudience.Name,
			AccessTokenTTL,
		),
	)

	kit.SetHttpOnlyCookie(w, s.clientOrigin, "accessToken", accessToken, int(AccessTokenTTL.Seconds()))
}

func (s *Server) handleMakeApiTokens(w http.ResponseWriter, r *http.Request) {

	// requested audience
	aud := r.URL.Query().Get("aud")
	if aud == "" {
		kit.Error(w, "'aud' query parameter uspecified", http.StatusBadRequest)
		return
	}

	// check that supplied audience name is one of the names available for
	//   users to request.
	nameIsValid := false
	for _, name := range validAudNames {
		if name == aud {
			nameIsValid = true
			break
		}
	}

	if !nameIsValid { // opaque error to hinder malicious probing on audience names
		kit.Error(w, "", http.StatusUnauthorized)
		return
	}

	accessToken := r.Context().Value(kit.CookieNameAccessToken).(jwt.Jwt)
	apiToken := s.jwtIssuer.StringifyJwt(
		s.jwtIssuer.MintToken(
			accessToken.Body.Subject,
			aud,
			ApiTokenTTL,
		),
	)

	kit.SetHttpOnlyCookie(w, s.clientOrigin, aud, apiToken, int(ApiTokenTTL.Seconds()))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	for _, name := range append(validAudNames, "refreshToken", "accessToken") {
		kit.DeleteCookie(w, name)
	}
}

// Returns true, nil when the users exists, and the given password hashes to
// the stored password hash.
func verifyPassword(db *sql.DB, username, password string) (bool, error) {
	storedUser, err := dbkit.GetUser(db, dbkit.DeriveUserId(username))

	if err != nil {
		return false, err
	}

	dbSalt, _ := base64.StdEncoding.DecodeString(storedUser.HashSaltB64)
	dbHash, _ := base64.StdEncoding.DecodeString(storedUser.HashedPwdB64)

	// hash the given pass and compare it to stored hash
	if subtle.ConstantTimeCompare(
		dbkit.HashString(password, dbSalt),
		dbHash,
	) != 1 { // hash mismatch
		return false, nil
	}

	return true, nil
}
