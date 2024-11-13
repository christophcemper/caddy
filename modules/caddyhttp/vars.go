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

	// first call to ContextWithVars() will create the VarsRWMutex to intialize and verify ENV
	_ = ContextWithVars(context.Background(), make(map[string]any))

}

const VarsRWMutexCtxKey caddy.CtxKey = "vars_rwmutex"

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
	return getVarsAndReadLockPurpose(ctx, "no purpose?")
}

func getVarsAndReadLockPurpose(ctx context.Context, purpose string) (map[string]any, func(), bool) {
	rwMutex, ok := ctx.Value(VarsRWMutexCtxKey).(*rwmutexplus.RWMutexPlus)
	if !ok {
		fmt.Printf("getVarsAndReadLock: no rwmutexplus.RWMutexPlus in context\n")
		return nil, nil, false
	}
	rwMutex.RLockWithPurpose(purpose)

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
	rwMutex, ok := ctx.Value(VarsRWMutexCtxKey).(*rwmutexplus.RWMutexPlus)
	if !ok {
		fmt.Printf("getVarsAndWriteLock: no rwmutexplus.RWMutexPlus in context\n")
		return nil, nil, false
	}
	rwMutex.LockWithPurpose(purpose)
	// rwMutex.RLock()

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
	_, unlock, ok := getVarsAndReadLockPurpose(r.Context(), fmt.Sprintf("VarsMiddleware.ServeHTTP %s", url))
	if !ok {
		fmt.Printf("VarsMiddleware.ServeHTTP %s: no vars map in context\n", url)
		return next.ServeHTTP(w, r)
	}
	unlock()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for k, v := range m {
		keyExpanded := repl.ReplaceAll(k, "")
		if valStr, ok := v.(string); ok {
			v = repl.ReplaceAll(valStr, "")
		}
		vars, unlockWrite, ok := getVarsAndWriteLockPurpose(r.Context(), fmt.Sprintf("vars[%s]=%v (%s)", keyExpanded, v, url))
		if !ok {
			unlockWrite()
			fmt.Printf("VarsMiddleware.ServeHTTP %s: no vars map in context\n", url)
			return next.ServeHTTP(w, r)
		}

		vars[keyExpanded] = v

		unlockWrite()
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

	for d.Next() {
		if err := nextVar(true); err != nil {
			return err
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			if err := nextVar(false); err != nil {
				return err
			}
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

	vars, unlock, ok := getVarsAndReadLockPurpose(r.Context(), "VarsMatcher.Match")
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
	vars, unlock, ok := getVarsAndReadLockPurpose(r.Context(), "MatchVarsRE.Match")
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
	varMap, unlock, ok := getVarsAndReadLockPurpose(ctx, "GetVar "+key)
	if !ok {
		fmt.Printf("GetVar: no vars map in context\n")
		return nil
	}
	defer unlock()

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Caught panic in GetVar")
			// in case we crash, print the value of the key last
			if value, ok := varMap[key]; ok {
				fmt.Printf("varMap[%s]=%v", key, value)
			}
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

	return varMap[key]
}

// Update SetVar to use write lock
func SetVar(ctx context.Context, key string, value any) {
	value1 := strings.ReplaceAll(fmt.Sprintf("%v", value), "\n", "\\n")
	varMap, unlock, ok := getVarsAndWriteLockPurpose(ctx, fmt.Sprintf("SetVar %s=%v", key, value1))
	if !ok {
		fmt.Printf("SetVar: no vars map in context\n")
		return
	}
	defer unlock()

	if value == nil {
		if _, ok := varMap[key]; ok {
			delete(varMap, key)
			return
		}
	}
	varMap[key] = value
}

// ContextWithVars attaches a new vars map to the context protected by a write lock.
func ContextWithVars(ctx context.Context, vars map[string]any) context.Context {

	// check if the context already has a vars rwmutex
	varsRWMutex, ok := ctx.Value(VarsRWMutexCtxKey).(*rwmutexplus.RWMutexPlus)
	if !ok {
		// if not, create a new one
		varsRWMutexTimeout, err := caddy.ParseDuration(string(caddy.VarsRWMutexTimeout))
		if err != nil {
			varsRWMutexTimeout = 100 * time.Millisecond // default fallback
			//
			// we can still overrule this in the ENV, e.g.
			// RWMUTEXTPLUS_TIMEOUT=134ms
		}
		varsRWMutex = rwmutexplus.NewRWMutexPlus("VarsRWMutex", time.Duration(varsRWMutexTimeout), nil).
			WithDebugLevel(0).WithVerboseLevel(1) // TODO: make this dynamic from config/CLI flags
		// for now you can set these in the ENV, e.g.
		// RWMUTEXTPLUS_DEBUGLEVEL=1 RWMUTEXTPLUS_VERBOSELEVEL=2

		ctx = context.WithValue(ctx, VarsRWMutexCtxKey, varsRWMutex)
	}

	// check if the context already has a vars map
	// if not, set up the vars map with a write lock
	varsRWMutex.LockWithPurpose("ContextWithVars" + fmt.Sprintf(" %v", vars))
	defer varsRWMutex.Unlock()

	existingVars, ok := ctx.Value(VarsCtxKey).(map[string]any)
	if !ok {
		ctx = context.WithValue(ctx, VarsCtxKey, vars)

	} else {
		// if it does, update the existing vars map?!?!
		// for k, v := range vars {
		// 	existingVars[k] = v
		// }
		// or panic?
		// TODO: decide what to do - seems like this was never considered

		// dump the existing vars map
		fmt.Printf("existingVars: %v\n", existingVars)
		// don't panic, just log an error
		fmt.Printf("ERROR: vars map already exists in context and it should not, or was overwritten in the past?\n")
		rwmutexplus.DumpAllLockInfo()
		debug.PrintStack()
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
