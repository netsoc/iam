/*
 * Netsoc IAM
 *
 * API for managing and authenticating Netsoc users. 
 *
 * API version: 1.0.9
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package iam
// IssueTokenRequest struct for IssueTokenRequest
type IssueTokenRequest struct {
	// Duration of validity for token. Follows [Go's `time.Duration` format](https://pkg.go.dev/time#ParseDuration) 
	Duration string `json:"duration,omitempty"`
}
