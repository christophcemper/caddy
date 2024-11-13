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

package caddy

// ldflag: VarsRWMutexTimeout
//
// max time to acquire a lock for the Vars middleware RWPutexPlus library
// we should have no concurrency so any time here would be plenty, but it shows 100ms is needed sometimes
//
// Override this variable during `go build` with `-ldflags`:
//
//	-ldflags='-X github.com/caddyserver/caddy/v2.VarsRWMutexTimeout=200000'
//
// for example.

var VarsRWMutexTimeout string = "100ms"
