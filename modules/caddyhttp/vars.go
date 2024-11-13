// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyhttp

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/christophcemper/rwmutexplus"
)

func init() {
	caddy.RegisterModule(VarsMiddleware{})
	caddy.RegisterModule(VarsMatcher{})
	caddy.RegisterModule(MatchVarsRE{})
}

// VarsMiddleware is an HTTP middleware which sets variables to
// have values that can be used in the HTTP request handler
// chain. The primary way to access variables is with placeholders,
// which have the form: `{http.vars.variable_name}`, or with
// the `vars` and `vars_regexp` request matchers.
//
// The key is the variable name, and the value is the value of the
// variable. Both the name and value may use or contain placeholders.
type VarsMiddleware map[string]any

// CaddyModule returns the Caddy module information.
func (VarsMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.vars",
		New: func() caddy.Module { return new(VarsMiddleware) },
	}
}

// getVarsAndReadLock gets the vars map from context with a read lock.
// Returns the vars map and a function to unlock the shared mutex.
func getVarsAndReadLock(ctx context.Context) (map[string]any, func(), bool) {
	rwMutex, ok := ctx.Value(VarsRWMutexCtxKey).(*rwmutexplus.InstrumentedRWMutex)
	if !ok {
		fmt.Printf("getVarsAndReadLock: no rwmutexplus.InstrumentedRWMutex in context\n")
		return nil, nil, false
	}
	rwMutex.RLock()

	vars, ok := ctx.Value(VarsCtxKey).(map[string]any)
	if !ok {
		rwMutex.RUnlock()
		fmt.Printf("getVarsAndReadLock: no vars map in context\n")
		return nil, nil, false
	}

	return vars, rwMutex.RUnlock, true
}

// getVarsAndWriteLock gets the vars map from context with a write lock.
// Returns the vars map and a function to unlock the mutex.
func getVarsAndWriteLock(ctx context.Context) (map[string]any, func(), bool) {
	return getVarsAndWriteLockPurpose(ctx, "no purpose?")
}

// getVarsAndWriteLockPurpose gets the vars map from context with a write lock and sets the purpose of the mutex.
// Returns the vars map and a function to unlock the mutex.
func getVarsAndWriteLockPurpose(ctx context.Context, purpose string) (map[string]any, func(), bool) {
	rwMutex, ok := ctx.Value(VarsRWMutexCtxKey).(*rwmutexplus.InstrumentedRWMutex)
	if !ok {
		fmt.Printf("getVarsAndWriteLock: no rwmutexplus.InstrumentedRWMutex in context\n")
		return nil, nil, false
	}
	rwMutex.LockPurpose(purpose)

	vars, ok := ctx.Value(VarsCtxKey).(map[string]any)
	if !ok {
		rwMutex.Unlock()
		fmt.Printf("getVarsAndWriteLock: no vars map in context\n")
		return nil, nil, false
	}

	return vars, rwMutex.Unlock, true
}

// Update ServeHTTP to use write lock
func (m VarsMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	// set the purpose of the mutex to the name of the handler method
	// so we can see which handler is holding the lock in the debug output
	// get URL from original request
	url := "URL?"
	if r != nil && r.URL != nil {
		url = r.URL.String()
	}
	vars, unlock, ok := getVarsAndWriteLockPurpose(r.Context(), fmt.Sprintf("VarsMiddleware.ServeHTTP %s", url))
	if !ok {
		fmt.Printf("VarsMiddleware.ServeHTTP %s: no vars map in context\n", url)
		return next.ServeHTTP(w, r)
	}
	defer unlock()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for k, v := range m {
		keyExpanded := repl.ReplaceAll(k, "")
		if valStr, ok := v.(string); ok {
			v = repl.ReplaceAll(valStr, "")
		}
		vars[keyExpanded] = v

		// Special case: the user ID is in the replacer, pulled from there
		// for access logs. Allow users to override it with the vars handler.
		if keyExpanded == "http.auth.user.id" {
			repl.Set(keyExpanded, v)
		}
	}

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	vars [<name> <val>] {
//	    <name> <val>
//	    ...
//	}
func (m *VarsMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	if *m == nil {
		*m = make(VarsMiddleware)
	}

	nextVar := func(headerLine bool) error {
		if headerLine {
			// header line is optional
			if !d.NextArg() {
				return nil
			}
		}
		varName := d.Val()

		if !d.NextArg() {
			return d.ArgErr()
		}
		varValue := d.ScalarVal()

		(*m)[varName] = varValue

		if d.NextArg() {
			return d.ArgErr()
		}
		return nil
	}

	if err := nextVar(true); err != nil {
		return err
	}
	for d.NextBlock(0) {
		if err := nextVar(false); err != nil {
			return err
		}
	}

	return nil
}

// VarsMatcher is an HTTP request matcher which can match
// requests based on variables in the context or placeholder
// values. The key is the placeholder or name of the variable,
// and the values are possible values the variable can be in
// order to match (logical OR'ed).
//
// If the key is surrounded by `{ }` it is assumed to be a
// placeholder. Otherwise, it will be considered a variable
// name.
//
// Placeholders in the keys are not expanded, but
// placeholders in the values are.
type VarsMatcher map[string][]string

// CaddyModule returns the Caddy module information.
func (VarsMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.vars",
		New: func() caddy.Module { return new(VarsMatcher) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *VarsMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string][]string)
	}
	// iterate to merge multiple matchers into one
	for d.Next() {
		var field string
		if !d.Args(&field) {
			return d.Errf("malformed vars matcher: expected field name")
		}
		vals := d.RemainingArgs()
		if len(vals) == 0 {
			return d.Errf("malformed vars matcher: expected at least one value to match against")
		}
		(*m)[field] = append((*m)[field], vals...)
		if d.NextBlock(0) {
			return d.Err("malformed vars matcher: blocks are not supported")
		}
	}
	return nil
}

// Update Match to use read lock
func (m VarsMatcher) Match(r *http.Request) bool {
	if len(m) == 0 {
		return true
	}

	vars, unlock, ok := getVarsAndReadLock(r.Context())
	if !ok {
		return false
	}
	defer unlock()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	for key, vals := range m {
		var varValue any
		if strings.HasPrefix(key, "{") &&
			strings.HasSuffix(key, "}") &&
			strings.Count(key, "{") == 1 {
			varValue, _ = repl.Get(strings.Trim(key, "{}"))
		} else {
			varValue = vars[key]
		}

		// see if any of the values given in the matcher match the actual value
		for _, v := range vals {
			matcherValExpanded := repl.ReplaceAll(v, "")
			var varStr string
			switch vv := varValue.(type) {
			case string:
				varStr = vv
			case fmt.Stringer:
				varStr = vv.String()
			case error:
				varStr = vv.Error()
			case nil:
				varStr = ""
			default:
				varStr = fmt.Sprintf("%v", vv)
			}
			if varStr == matcherValExpanded {
				return true
			}
		}
	}
	return false
}

// MatchVarsRE matches the value of the context variables by a given regular expression.
//
// Upon a match, it adds placeholders to the request: `{http.regexp.name.capture_group}`
// where `name` is the regular expression's name, and `capture_group` is either
// the named or positional capture group from the expression itself. If no name
// is given, then the placeholder omits the name: `{http.regexp.capture_group}`
// (potentially leading to collisions).
type MatchVarsRE map[string]*MatchRegexp

// CaddyModule returns the Caddy module information.
func (MatchVarsRE) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.vars_regexp",
		New: func() caddy.Module { return new(MatchVarsRE) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchVarsRE) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string]*MatchRegexp)
	}
	// iterate to merge multiple matchers into one
	for d.Next() {
		var first, second, third string
		if !d.Args(&first, &second) {
			return d.ArgErr()
		}

		var name, field, val string
		if d.Args(&third) {
			name = first
			field = second
			val = third
		} else {
			field = first
			val = second
		}

		// Default to the named matcher's name, if no regexp name is provided
		if name == "" {
			name = d.GetContextString(caddyfile.MatcherNameCtxKey)
		}

		(*m)[field] = &MatchRegexp{Pattern: val, Name: name}
		if d.NextBlock(0) {
			return d.Err("malformed vars_regexp matcher: blocks are not supported")
		}
	}
	return nil
}

// Provision compiles m's regular expressions.
func (m MatchVarsRE) Provision(ctx caddy.Context) error {
	for _, rm := range m {
		err := rm.Provision(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// Update Match to use read lock
func (m MatchVarsRE) Match(r *http.Request) bool {
	vars, unlock, ok := getVarsAndReadLock(r.Context())
	if !ok {
		return false
	}
	defer unlock()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for key, val := range m {
		var varValue any
		if strings.HasPrefix(key, "{") &&
			strings.HasSuffix(key, "}") &&
			strings.Count(key, "{") == 1 {
			varValue, _ = repl.Get(strings.Trim(key, "{}"))
		} else {
			varValue = vars[key]
		}

		var varStr string
		switch vv := varValue.(type) {
		case string:
			varStr = vv
		case fmt.Stringer:
			varStr = vv.String()
		case error:
			varStr = vv.Error()
		case nil:
			varStr = ""
		default:
			varStr = fmt.Sprintf("%v", vv)
		}

		valExpanded := repl.ReplaceAll(varStr, "")
		if match := val.Match(valExpanded, repl); match {
			return match
		}
	}
	return false
}

// Validate validates m's regular expressions.
func (m MatchVarsRE) Validate() error {
	for _, rm := range m {
		err := rm.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// Update GetVar to use read lock
func GetVar(ctx context.Context, key string) any {
	varMap, unlock, ok := getVarsAndReadLock(ctx)
	if !ok {
		fmt.Printf("GetVar: no vars map in context\n")
		return nil
	}
	defer unlock()

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Caught panic in GetVar")
			fmt.Printf("Stack trace:\n%s\n", debug.Stack())
			caddy.DumpContext(ctx)
		}
	}()

	// temporary panic simulation
	if key == "client_ip" {
		origReq, ok := ctx.Value(OriginalRequestCtxKey).(http.Request)
		if ok && origReq.URL != nil {
			// fmt.Printf("\n- %s: %s - %s - %v - ", "origReq", origReq.URL.Path, origReq.RemoteAddr, origReq.Header)

			// if the URL contains the string "&search=PANICNOW" then simulate a panic
			// but only if the client IP starts with local IP range 10. or 172. or 192.
			if strings.Contains(origReq.URL.String(), "&search=PANICNOW") &&
				(strings.HasPrefix(origReq.RemoteAddr, "10.") ||
					strings.HasPrefix(origReq.RemoteAddr, "172.") ||
					strings.HasPrefix(origReq.RemoteAddr, "192.") ||
					strings.HasPrefix(origReq.RemoteAddr, "127.0.0.1")) {
				caddy.DumpContext(ctx)

				simulatePanic(true)
			}
		}
	}

	// in case we crash, print the value of the key last
	value := varMap[key]
	if key == "client_ip" {
		fmt.Printf("%s", value)
	}

	return varMap[key]
}

// Update SetVar to use write lock
func SetVar(ctx context.Context, key string, value any) {
	vars, unlock, ok := getVarsAndWriteLockPurpose(ctx, fmt.Sprintf("SetVar %s=%v", key, value))
	if !ok {
		fmt.Printf("SetVar: no vars map in context\n")
		return
	}
	// defer unlock()

	if value == nil {
		if _, ok := vars[key]; ok {
			delete(vars, key)
			unlock()
			return
		}
	}
	vars[key] = value

	unlock()
}

// ContextWithVars attaches a new vars map to the context protected by a write lock.
func ContextWithVars(ctx context.Context, vars map[string]any) context.Context {

	// check if the context already has a vars rwmutex
	varsRWMutex, ok := ctx.Value(VarsRWMutexCtxKey).(*rwmutexplus.InstrumentedRWMutex)
	if !ok {
		// if not, create a new one

		varsRWMutexTimeout := time.Duration(VarsRWMutexMillis) * time.Millisecond

		// max time to acquire a lock configured via Caddyfile
		// if app.VarsLockTimeout > 0 {
		// 	varsRWMutexTimeout = time.Duration(app.VarsLockTimeout)
		// }

		varsRWMutex = rwmutexplus.NewInstrumentedRWMutex(time.Duration(varsRWMutexTimeout))
		ctx = context.WithValue(ctx, VarsRWMutexCtxKey, varsRWMutex)
	}

	// check if the context already has a vars map
	existingVars, ok := ctx.Value(VarsCtxKey).(map[string]any)
	if !ok {
		// if not, set up the vars map with a write lock
		varsRWMutex.Lock()
		ctx = context.WithValue(ctx, VarsCtxKey, vars)
		varsRWMutex.Unlock()
	} else {
		// if it does, update the existing vars map?!?!
		// for k, v := range vars {
		// 	existingVars[k] = v
		// }
		// or panic?
		// TODO: decide what to do - seems like this was never considered

		// dump the existing vars map
		fmt.Printf("existingVars: %v\n", existingVars)
		panic("vars map already exists in context and it should not, or was overwritten in the past?")
	}

	return ctx
}

// ReqWithVars attaches a new vars map to the request context protected by a write lock.
func ReqWithVars(req *http.Request, vars map[string]any) *http.Request {

	// get the original request context
	ctx := req.Context()

	// attach the vars map to the context protected by a write lock
	return req.WithContext(ContextWithVars(ctx, vars))

}

// Interface guards
var (
	_ MiddlewareHandler     = (*VarsMiddleware)(nil)
	_ caddyfile.Unmarshaler = (*VarsMiddleware)(nil)
	_ RequestMatcher        = (*VarsMatcher)(nil)
	_ caddyfile.Unmarshaler = (*VarsMatcher)(nil)
)

func simulatePanic(shouldPanic bool) {
	fmt.Printf("- %s: %v\n", "simulatePanic", shouldPanic)
	if shouldPanic {
		fmt.Println("TEST-PANIC: Simulated panic for log testing")
		fmt.Println("    ___________________")
		fmt.Println("   /                   \\")
		fmt.Println("  /   ⊙     ┗┫     ⊙   \\")
		fmt.Println(" |     ╭─────┴─────╮     |")
		fmt.Println(" |     │           │     |")
		fmt.Println(" |     │    ╭╮    │     |")
		fmt.Println(" |     │   ╭──╮   │     |")
		fmt.Println(" |     │    ╰╯    │     |")
		fmt.Println("  \\     \\         /     /")
		fmt.Println("   \\     \\_______/     /")
		fmt.Println("    \\                 /")
		fmt.Println("     \\_______________/")
		fmt.Println("      ||  ||  ||  ||")
		fmt.Println("      ||  ||  ||  ||")
		fmt.Println("      \\/  \\/  \\/  \\/")
		fmt.Println("    AAAAAAAAAAAAAAAAAA")
		fmt.Println("    AAAAAAAAAAAAAAAAAA")
		fmt.Println("    AAAAAAAAAAAAAAAAAA")
		panic("TEST-PANIC: Simulated panic for log testing")
	}
}

// Add this with the other context keys at the package level
var HTTPRequestCtxKey = caddy.CtxKey("http_request")
