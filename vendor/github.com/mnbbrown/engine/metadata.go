package engine

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/satori/go.uuid"
	"net/http"
	"runtime"
	"time"
)

// RequestMetadata generates metadata info for each request
type RequestMetadata struct {
	RequestID string
	Method    string
	Path      string
	Status    int
	IP        string
	Size      int
	Latency   time.Duration
	StartTime time.Time
}

// Logger returns a logger that logs with the request fields
func (r *RequestMetadata) Logger() *log.Entry {
	return log.WithFields(r.fields())
}

func (r *RequestMetadata) fields() log.Fields {
	return log.Fields{
		"request_id": r.RequestID,
		"remote_ip":  r.IP,
	}
}

type key int

const metadataCtxKey key = 0

// M is middleware that adds metadata to each requests and logs
func MetadataMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		start := time.Now().UTC()

		metadata := &RequestMetadata{
			RequestID: uuid.NewV4().String(),
			StartTime: start,
			Method:    req.Method,
			Path:      req.URL.Path,
		}
		req.Header.Set("X-Request-Id", metadata.RequestID)
		rw.Header().Set("Request-Id", metadata.RequestID)

		metadata.IP = req.Header.Get("X-Real-IP")
		if metadata.IP == "" {
			metadata.IP = req.Header.Get("X-Forwarded-For")
			if metadata.IP == "" {
				metadata.IP = req.RemoteAddr
			}
		}

		// Set context
		GetContext(req).Set(metadataCtxKey, metadata)

		// Use StatusStoringRequest to keep a track of the request status.
		rw = NewResponseWriter(rw)

		defer func() {
			if err := recover(); err != nil {
				buf := make([]byte, 1<<16)
				stackSize := runtime.Stack(buf, true)
				metadata.Logger().Error(err)
				metadata.Logger().Errorf("%s", string(buf[0:stackSize]))
				JSONError(rw, errors.New("Ooops. Something went wrong on our end"), http.StatusInternalServerError)
			}

			resp := rw.(*ResponseWriter)
			metadata.Status = resp.Status()
			metadata.Size = resp.Length()
			statusColor := ColourForStatus(metadata.Status)
			metadata.Latency = time.Since(start)

			log.WithFields(metadata.fields()).WithFields(log.Fields{
				"remote_ip": metadata.IP,
				"method":    metadata.Method,
				"path":      metadata.Path,
				"size":      metadata.Size,
				"latency":   metadata.Latency,
				"status":    metadata.Status,
			}).Printf("%s\t| %s | %s%d%s | %v | %s", metadata.Path, metadata.Method, statusColor, metadata.Status, ResetColour, metadata.Latency, HumanSize(metadata.Size))
		}()

		// Serve
		next.ServeHTTP(rw, req)
	})
}

// FromContext extracts the metadata from the request
func GetMetadata(ctx *Context) (*RequestMetadata, bool) {
	md, ok := ctx.Value(metadataCtxKey).(*RequestMetadata)
	return md, ok
}
