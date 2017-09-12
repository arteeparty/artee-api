package routes

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mnbbrown/artee/datastore"
	"github.com/mnbbrown/engine"
	"github.com/sfreiberg/gotwilio"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

func generateOTP() string {
	b := make([]byte, 6)
	n, err := io.ReadAtLeast(rand.Reader, b, 6)
	if n != 6 {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b)
}

func getUser(ctx *engine.Context) (*datastore.User, bool) {
	user, ok := ctx.Value("user").(*datastore.User)
	return user, ok
}

// HandleLogin sends a confirmation text message
func HandleLogin(rw http.ResponseWriter, req *http.Request) {
	j, _ := engine.ParseJSON(req)
	phone := j.GetString("phone")
	if phone == "" {
		engine.JSON(rw, &engine.J{"message": "phone is required"}, http.StatusBadRequest)
		return
	}
	ctx := engine.GetContext(req)
	md, _ := engine.GetMetadata(ctx)
	userService := datastore.FromContext(ctx).UserService
	user, err := userService.GetUserByPhone(phone)

	twilio := gotwilio.NewTwilioClient(os.Getenv("TW_ACCOUNT_SID"), os.Getenv("TW_AUTH_TOKEN"))
	token := generateOTP()
	message := fmt.Sprintf("Your artee party code is %s", token)
	twilio.SendSMS("+61419297613", phone, message, "", "")

	if user == nil {
		userToSave := &datastore.User{
			Phone: phone,
			Name:  "TEMP_NAME",
		}
		userToSave.SetPassword(token)
		err = userService.InsertUser(userToSave)
		if err != nil {
			md.Logger().Println(err)
			engine.JSON(rw, &engine.J{"message": "Internal Server Error"}, http.StatusInternalServerError)
			return
		}
		user = userToSave
	} else {
		err = userService.SetOTP(phone, token)
		if err != nil {
			md.Logger().Println(err)
			engine.JSON(rw, &engine.J{"message": "Internal Server Error"}, http.StatusInternalServerError)
			return
		}
	}
	rw.WriteHeader(http.StatusCreated)
}

// HandleConfirm verifies a users phone and password and returns a JWT
func HandleConfirm(rw http.ResponseWriter, req *http.Request) {
	ctx := engine.GetContext(req)
	md, _ := engine.GetMetadata(ctx)
	j, _ := engine.ParseJSON(req)
	phone := j.GetString("phone")
	token := j.GetString("token")

	if phone == "" || token == "" {
		engine.JSON(rw, &engine.J{"message": "Both phone and token are required."}, http.StatusBadRequest)
		return
	}

	user, err := datastore.FromContext(ctx).UserService.GetUserByPhone(phone)
	if err != nil {
		md.Logger().Println(err)
		engine.JSON(rw, &engine.J{"message": "Bad phone or password"}, http.StatusUnauthorized)
		return
	}

	if ok := user.IsCorrectPassword(token); !ok {
		engine.JSON(rw, &engine.J{"message": "Bad phone or token"}, http.StatusUnauthorized)
		return
	}

	accessToken := jwt.New(jwt.SigningMethodHS256)
	accessToken.Claims["id"] = user.ID
	accessToken.Claims["phone"] = phone
	accessToken.Claims["name"] = user.Name
	accessToken.Claims["type"] = "access"
	accessToken.Claims["nbf"] = time.Now().Unix()
	accessToken.Claims["exp"] = time.Now().Add(time.Minute * 10).Unix()

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshToken.Claims["id"] = user.ID
	refreshToken.Claims["phone"] = phone
	refreshToken.Claims["name"] = user.Name
	refreshToken.Claims["nbf"] = time.Now().Unix()
	refreshToken.Claims["type"] = "refresh"
	refreshToken.Claims["exp"] = time.Now().Add(time.Hour * 30 * 24).Unix()

	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "RANDOME_SECRET_KEY"
	}
	accessTokenString, err := accessToken.SignedString([]byte(secret))
	if err != nil {
		md.Logger().Println(err)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	refreshTokenString, err := refreshToken.SignedString([]byte(secret))
	if err != nil {
		md.Logger().Println(err)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	engine.JSON(rw, &engine.J{"access_token": accessTokenString, "refresh_token": refreshTokenString, "profile": map[string]string{
		"phone": phone,
		"name":  user.Name,
		"id":    user.ID,
	}}, 200)

}

// HandleRefresh generates a new access token in return for a refresh token
func HandleRefresh(rw http.ResponseWriter, req *http.Request) {
	ctx := engine.GetContext(req)
	user, ok := getUser(ctx)
	if !ok {
		engine.JSON(rw, errors.New("Not Authenticated"), http.StatusUnauthorized)
		return
	}

	accessToken := jwt.New(jwt.SigningMethodHS256)
	accessToken.Claims["id"] = user.ID
	accessToken.Claims["phone"] = user.Phone
	accessToken.Claims["name"] = user.Name
	accessToken.Claims["type"] = "access"
	accessToken.Claims["nbf"] = time.Now().Unix()
	accessToken.Claims["exp"] = time.Now().Add(time.Minute * 10).Unix()

	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "RANDOME_SECRET_KEY"
	}
	accessTokenString, err := accessToken.SignedString([]byte(secret))
	if err != nil {
		md, _ := engine.GetMetadata(ctx)
		md.Logger().Println(err)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	engine.JSON(rw, &engine.J{"access_token": accessTokenString}, 200)
}

// HandleMe returns details about the current user
func HandleMe(rw http.ResponseWriter, req *http.Request) {
	ctx := engine.GetContext(req)

	user, ok := ctx.Value("user").(*datastore.User)
	if !ok {
		engine.JSON(rw, errors.New("Not Authenticated"), http.StatusUnauthorized)
		return
	}
	engine.JSON(rw, user, http.StatusOK)
}

// TokenVerificationMiddleware verifies a user is authneticated
func TokenVerificationMiddleware(tokenType string) engine.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

			ctx := engine.GetContext(req)

			// Get Authorization header.
			authHeader := req.Header.Get("Authorization")
			if authHeader == "" {
				engine.JSON(rw, errors.New("Authorization Header not set"), http.StatusUnauthorized)
				return
			}

			// Ensure the format is correct.
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 {
				engine.JSON(rw, errors.New("Format is Authorization: Bearer [token]"), http.StatusUnauthorized)
				return
			}

			md, _ := engine.GetMetadata(ctx)

			// Parse and verify the token
			token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				secret := os.Getenv("AUTH_SECRET")
				if secret == "" {
					secret = "RANDOME_SECRET_KEY"
				}
				return []byte(secret), nil
			})

			if err == nil && token.Valid {

				if token.Claims["type"] != tokenType {
					engine.JSON(rw, errors.New("Invalid token"), http.StatusUnauthorized)
					return
				}

				user, err := datastore.FromContext(ctx).UserService.GetUser(token.Claims["id"].(string))
				if err != nil {
					engine.JSON(rw, errors.New("Invalid Authorization header"), http.StatusUnauthorized)
					return
				}
				engine.GetContext(req).Set("user", user)
				next.ServeHTTP(rw, req)
				return

			} else if ve, ok := err.(*jwt.ValidationError); ok {
				if ve.Errors&jwt.ValidationErrorMalformed != 0 {
					md.Logger().Println("Token not recognised.")
					engine.JSON(rw, errors.New("Invalid Authorization header"), http.StatusUnauthorized)
					return
				} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
					md.Logger().Println("JWT that is expired or not yet in effect.")
					engine.JSON(rw, errors.New("Invalid Authorization header"), http.StatusUnauthorized)
					return
				} else {
					md.Logger().Println("Bad Token", err)
					engine.JSON(rw, errors.New("Invalid Authorization header"), http.StatusUnauthorized)
					return
				}
			} else {
				md.Logger().Println("Bad Token", err)
				engine.JSON(rw, errors.New("Invalid Authorization header"), http.StatusUnauthorized)
				return
			}
		})
	}
}
