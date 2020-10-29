package main

import (
	"log"
	"net/http"
)

func main() {
	// "Signin" and "Welcome" are the handlers that we will implement
	http.HandleFunc("/login", Signin)
	http.Handle("/welcome", authMiddleware(http.HandlerFunc(Welcome)))
	http.HandleFunc("/refresh", Refresh)

	// start the server on port 3000
	log.Fatal(http.ListenAndServe(":3000", nil))
}
