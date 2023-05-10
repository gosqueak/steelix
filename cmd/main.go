package main

import (
	"github.com/gosqueak/jwt"
	"github.com/gosqueak/jwt/rs256"
	"github.com/gosqueak/umbreon/api"
	"github.com/gosqueak/umbreon/database"
)

const (
	Addr       = "0.0.0.0:8081"
	JwtActorId = "AUTHSERVICE"
)

func main() {
	db := database.Load("users.sqlite")

	keyBytes, err := rs256.LoadKeyBytes("jwtrsa.private")
	if err != nil {
		panic(err)
	}

	iss := jwt.NewIssuer(
		rs256.ParsePrivateBytes(keyBytes),
		JwtActorId,
	)
	aud := jwt.NewAudience(
		iss.PublicKey(),
		JwtActorId,
	)

	serv := api.NewServer(Addr, db, iss, aud)
	serv.Run()
}
