package datastore

import (
	"database/sql"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // Import postgresql
	"github.com/mnbbrown/engine"
	"net/http"
)

type key int

const reqKey int = 0

// NewDatastore creates a new datastore
func NewDatastore(dsn string) *Datastore {
	db := sqlx.MustConnect("postgres", dsn)
	return &Datastore{db, NewUserService(db), sql.ErrNoRows}
}

// Datastore is a data access layer
type Datastore struct {
	*sqlx.DB
	*UserService
	ErrNoRows error
}

// M is middleware to inject datastore from request contest
func (d *Datastore) M() engine.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			ctx := engine.GetContext(req)
			ctx.Set(reqKey, d)
			next.ServeHTTP(rw, req)
		})
	}
}

// FromContext extracts the datastore from the request context
func FromContext(ctx *engine.Context) *Datastore {
	return ctx.Value(reqKey).(*Datastore)
}
