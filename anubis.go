// Package anubis contains the version number of Anubis.
package anubis

import "time"

// Version is the current version of Anubis.
//
// This variable is set at build time using the -X linker flag. If not set,
// it defaults to "devel".
var Version = "devel"

// CookieName is the name of the cookie that Anubis uses in order to validate
// access.
var CookieName = "techaro.lol-anubis-auth"

// TestCookieName is the name of the cookie that Anubis uses in order to check
// if cookies are enabled on the client's browser.
var TestCookieName = "techaro.lol-anubis-cookie-verification"

// CookieDefaultExpirationTime is the amount of time before the cookie/JWT expires.
const CookieDefaultExpirationTime = 7 * 24 * time.Hour

// BasePrefix is a global prefix for all Anubis endpoints. Can be emptied to remove the prefix entirely.
var BasePrefix = ""

// StaticPath is the location where all static Anubis assets are located.
const StaticPath = "/.within.website/x/cmd/anubis/"

// APIPrefix is the location where all Anubis API endpoints are located.
const APIPrefix = "/.within.website/x/cmd/anubis/api/"

// DefaultDifficulty is the default "difficulty" (number of leading zeroes)
// that must be met by the client in order to pass the challenge.
const DefaultDifficulty = 4

// ForcedLanguage is the language being used instead of the one of the request's Accept-Language header
// if being set.
var ForcedLanguage = ""
