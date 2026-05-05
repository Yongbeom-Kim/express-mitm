
clean:
	rm -rf $(HOME)/.express-mitm

gen-ca:
	go run ./cmd/gen-ca