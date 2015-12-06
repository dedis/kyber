package cipher

import (
	"golang.org/x/net/context"
)

type contextKey struct{}

// Create a Context derived from the given parent context
// but configured with the given symmetric cipher Suite.
func Context(parent context.Context, cipher Suite) context.Context {
	return context.WithValue(parent, contextKey{}, cipher)
}

// Returns the Suite a context is configured with, or nil if none.
func Get(ctx context.Context) (cipher Suite) {
	cipher, _ = ctx.Value(contextKey{}).(Suite)
	return
}
