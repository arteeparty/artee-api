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

// HandleLogin sends a confirmation text message
func HandleLogin(rw http.ResponseWriter, req *http.Request) {
	j := engine.ParseJSON(req)
	phone, ok := j["phone"]
	if !ok {
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
		err = userService.InsertUser(user)
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
	j := engine.ParseJSON(req)
	phone, ok := j["phone"]

	if !ok {
		engine.JSON(rw, &engine.J{"message": "Both phone and token are required."}, http.StatusBadRequest)
		return
	}

	token, ok := j["token"]

	if !ok {
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

	jwtToken := jwt.New(jwt.SigningMethodHS256)
	jwtToken.Claims["id"] = user.ID
	jwtToken.Claims["phone"] = phone
	jwtToken.Claims["name"] = user.Name
	jwtToken.Claims["nbf"] = time.Now().Unix()
	jwtToken.Claims["exp"] = time.Now().Add(time.Hour * 8).Unix()

	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "RANDOME_SECRET_KEY"
	}
	tokenString, err := jwtToken.SignedString([]byte(secret))
	if err != nil {
		md.Logger().Println(err)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	engine.JSON(rw, &engine.J{"token": tokenString, "phone": phone}, 200)

}

// HandleRegister registers a new user
func HandleRegister(rw http.ResponseWriter, req *http.Request) {
	ctx := engine.GetContext(req)
	ds := datastore.FromContext(ctx)

	name := req.FormValue("last_name")
	phone := req.FormValue("phone")
	email := req.FormValue("email")
	plainTextPassword := req.FormValue("password")

	if name == "" {
		engine.JSON(rw, &engine.J{"error": "name is required", "status_code": http.StatusBadRequest}, http.StatusBadRequest)
		return
	}

	user := &datastore.User{
		Name:  name,
		Email: email,
		Phone: phone,
	}

	exists, err := ds.UserService.CheckEmail(email)
	if err != nil {
		fmt.Println(err)
		engine.JSON(rw, &engine.J{"error": http.StatusText(http.StatusInternalServerError), "status_code": http.StatusInternalServerError}, http.StatusInternalServerError)
		return
	}
	if exists {
		engine.JSON(rw, &engine.J{"error": "A User with that email already exists.", "status_code": 409}, 409)
		return
	}

	err = user.SetPassword(plainTextPassword)
	if err != nil {
		fmt.Println(err)
		engine.JSON(rw, &engine.J{"error": http.StatusText(http.StatusInternalServerError), "status_code": http.StatusInternalServerError}, http.StatusInternalServerError)
		return
	}

	if err := ds.UserService.InsertUser(user); err != nil {
		fmt.Println(err)
		engine.JSON(rw, &engine.J{"error": http.StatusText(http.StatusInternalServerError), "status_code": http.StatusInternalServerError}, http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusCreated)
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
func TokenVerificationMiddleware(next http.Handler) http.Handler {
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
