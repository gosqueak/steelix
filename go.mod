module github.com/gosqueak/steelix

go 1.20

require (
	github.com/gosqueak/apikit v0.0.0-20230512061655-69436fe1a189
	github.com/gosqueak/jwt v0.0.0-20230510165842-1b5cd2f15c4b
	github.com/gosqueak/leader v0.0.0-20230517042050-838f23b14bd7
	github.com/mattn/go-sqlite3 v1.14.16
	golang.org/x/crypto v0.9.0
)

replace github.com/gosqueak/leader => ../leader
