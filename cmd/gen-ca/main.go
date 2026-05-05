package main

import (
	"log"

	cacert "github.com/Yongbeom-Kim/express-mitm/internal/ca-cert"
)

func main() {
	if _, _, err := cacert.GenerateCaCert(); err != nil {
		log.Fatal(err)
	}
}
