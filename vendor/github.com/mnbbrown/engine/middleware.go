package engine

import (
	"fmt"
	"net/http"
	"strings"
)

func CORSAcceptAll(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method == "OPTIONS" {
			rw.Header().Set("Access-Control-Allow-Methods", "*")
			rw.Header().Set("Access-Control-Allow-Origin", "*")
			rw.Header().Set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization")
			rw.WriteHeader(200)
			return
		} else {
			rw.Header().Set("Access-Control-Allow-Methods", "*")
			rw.Header().Set("Access-Control-Allow-Origin", "*")
			rw.Header().Set("Access-Control-Allow-Headers", "*")
			next.ServeHTTP(rw, req)
		}
	})
}

type CORSConfig struct {
	AllowedMethods []string
	AllowedOrigins []string
	AllowedHeaders []string
}

var AllowAllConfig = &CORSConfig{
	AllowedMethods: []string{"*"},
	AllowedOrigins: []string{"*"},
	AllowedHeaders: []string{"Authorization", "X-Requested-With"},
}

func CORSMiddleware(config *CORSConfig) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			fmt.Println(req.Method)
			switch {
			case req.Method == "OPTIONS":
				rw.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				rw.Header().Set("Access-Control-Allow-Origin", strings.Join(config.AllowedOrigins, ", "))
				rw.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
				rw.WriteHeader(200)
				return
			default:
				rw.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				rw.Header().Set("Access-Control-Allow-Origin", strings.Join(config.AllowedOrigins, ", "))
				rw.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
				next.ServeHTTP(rw, req)
			}
		})
	}
}
