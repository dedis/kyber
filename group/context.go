package group

import (
	"golang.org/x/net/context"
)

type contextKey struct{}

// Create a Context derived from the given parent context
// but configured with the given cryptographic group.
func Context(parent context.Context, group Group) context.Context {
	return context.WithValue(parent, contextKey{}, group)
}

// Returns the group a context is configured with, or nil if none.
func Get(ctx context.Context) (group Group) {
	group, _ = ctx.Value(contextKey{}).(Group)
	return
}
