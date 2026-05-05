package main

import (
	"log"

	cacert "github.com/Yongbeom-Kim/express-mitm/internal/ca-cert"
)

func main() {
	authority := cacert.New()
	if err := authority.GenerateCaCert(); err != nil {
		log.Fatal(err)
	}
}
