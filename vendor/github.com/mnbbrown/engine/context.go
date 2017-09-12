package engine

import (
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
	"io"
	"net/http"
	"sync"
)

type Context struct {
	context.Context
	io.ReadCloser
	mutex  sync.RWMutex
	Params httprouter.Params
	store  map[interface{}]interface{}
}

func (c *Context) Wrap(ctx context.Context) {
	c.Context = ctx
}

func (c *Context) Set(key interface{}, value interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.store[key] = value
}

func (c *Context) Value(key interface{}) interface{} {
	c.mutex.RLock()
	if value, ok := c.store[key]; ok {
		c.mutex.RUnlock()
		return value
	}
	c.mutex.RUnlock()
	return c.Context.Value(key)
}

func GetContext(req *http.Request) *Context {
	ctx, ok := req.Body.(*Context)
	if !ok {
		ctx = &Context{
			ReadCloser: req.Body,
			Context:    context.Background(),
			store:      make(map[interface{}]interface{}),
		}
		req.Body = ctx
	}
	return ctx
}
