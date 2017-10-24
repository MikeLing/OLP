package middlewares

import (
	"crypto/subtle"
	"net/http"
)

func BasicAuth(handler http.HandlerFunc, username, password, realm string) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestUsername, requiestPassword, ok := r.BasicAuth()

		if !ok || subtle.ConstantTimeCompare([]byte(requestUsername), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(requiestPassword), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorised.\n"))
			return
		}

		handler(w, r)
	}
}
