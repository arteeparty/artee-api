package main

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/joho/godotenv"
	"github.com/mnbbrown/artee/datastore"
	"github.com/mnbbrown/artee/routes"
	"github.com/mnbbrown/engine"
	"github.com/satori/go.uuid"
	"net/http"
	"os"
	"strings"
	"time"
)

func generateTwilioAccessToken(accountSid string, apiKey string, apiSecret string) string {
	now := time.Now().UTC().Unix()
	payload := map[string]interface{}{
		"jti": fmt.Sprintf("%s-%d", apiKey, now),
		"iss": apiKey,
		"sub": accountSid,
		"exp": now + 3600,
		"grants": map[string]interface{}{
			"identity": fmt.Sprintf("api-%s", uuid.NewV4()),
			"video": map[string]string{
				"room": "test_room",
			},
		},
	}
	header := map[string]interface{}{
		"typ": "JWT",
		"cty": "twilio-fpa;v=1",
		"alg": "HS256",
	}
	segments := []string{encodeSegment(header), encodeSegment(payload)}
	signMe := strings.Join(segments, ".")
	signature := sign(crypto.SHA256, signMe, []byte(apiSecret))
	segments = append(segments, encodeBase64Url(signature))
	token := strings.Join(segments, ".")
	return token
}

func sign(hash crypto.Hash, msg string, key []byte) []byte {
	hasher := hmac.New(hash.New, key)
	hasher.Write([]byte(msg))

	return hasher.Sum(nil)
}

func encodeSegment(data map[string]interface{}) string {
	b, _ := json.Marshal(data)
	return encodeBase64Url(b)
}

func encodeBase64Url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func handleToken(rw http.ResponseWriter, req *http.Request) {
	accountSid := os.Getenv("TW_ACCOUNT_SID")
	apiKey := os.Getenv("TW_API_KEY")
	apiSecret := os.Getenv("TW_API_SECRET")
	token := generateTwilioAccessToken(accountSid, apiKey, apiSecret)
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(rw)
	enc.Encode(&map[string]string{
		"token": token,
	})
}

func handleVersion(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(rw)
	enc.Encode(&map[string]string{
		"version": "0.0.1",
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env found. Skipping")
	}

	ds := datastore.NewDatastore(os.Getenv("DATABASE_URL"))
	r := engine.NewRouter()
	r.Use(ds.M())

	r.Get("/", handleVersion)

	s := r.SubRouter("/auth")
	s.Post("/login", routes.HandleLogin)
	s.Post("/confirm", routes.HandleConfirm)
	s.Post("/refresh", routes.HandleRefresh, routes.TokenVerificationMiddleware("refresh"))

	api := r.SubRouter("/api", routes.TokenVerificationMiddleware("access"))
	api.Get("/token", handleToken)

	hub := newHub()
	go hub.run()
	http.Handle("/", engine.CORSAcceptAll(r))
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8001"
	}
	host, _ := os.Hostname()

	log.WithFields(log.Fields{
		"host": host,
		"port": port,
	}).Infoln("Listening for requests")

	http.ListenAndServe(":"+port, nil)
}
