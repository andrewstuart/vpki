// Package vtls provides a layer of abstraction between the golang stdlib
// crypto primitives and common crypto uses (e.g. serving HTTPS) and the
// functionality provided by Vault. Internally, the library generates RSA keys
// locally
package vtls
