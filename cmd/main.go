package main

import (
	"os"

	"github.com/gosqueak/jwt"
	"github.com/gosqueak/jwt/rs256"
	"github.com/gosqueak/leader/team"
	"github.com/gosqueak/steelix/api"
	"github.com/gosqueak/steelix/database"
)

func main() {
	tm := team.Download(os.Getenv("TEAMFILE_JSON_URL"))
	steelix := tm["steelix"]

	db := database.Load("users.sqlite")

	keyBytes, err := rs256.LoadKeyBytes("jwtrsa.private")
	if err != nil {
		panic(err)
	}

	iss := jwt.NewIssuer(
		rs256.ParsePrivateBytes(keyBytes),
		steelix.JWTInfo.IssuerName,
	)
	aud := jwt.NewAudience(
		iss.PublicKey(),
		steelix.JWTInfo.AudienceName,
	)

	serv := api.NewServer(steelix.ListenAddress, db, iss, aud)
	serv.Run()
}
