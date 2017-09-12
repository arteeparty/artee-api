package engine

import (
	"encoding/json"
	"errors"
	"net/http"
)

type J map[string]interface{}

func (j J) GetString(key string) string {
	s, ok := j[key]
	if !ok {
		return ""
	}
	return s.(string)
}

func JSON(rw http.ResponseWriter, v interface{}, code int) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(code)
	enc := json.NewEncoder(rw)
	enc.Encode(v)
}

func JSONError(rw http.ResponseWriter, err error, code int) {
	if err == nil {
		err = errors.New(http.StatusText(code))
	}
	JSON(rw, J{
		"status_code": code,
		"message":     err.Error(),
	}, code)
}

func ParseJSON(req *http.Request) (J, error) {
	j := J{}
	err := json.NewDecoder(req.Body).Decode(&j)
	return j, err
}
