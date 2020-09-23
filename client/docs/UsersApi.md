# \UsersApi

All URIs are relative to *https://iam.netsoc.ie/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateUser**](UsersApi.md#CreateUser) | **Post** /users | Create a new user
[**DeleteUser**](UsersApi.md#DeleteUser) | **Delete** /users/{username} | Delete a user by their username
[**GetUser**](UsersApi.md#GetUser) | **Get** /users/{username} | Get a user by their username
[**GetUsers**](UsersApi.md#GetUsers) | **Get** /users | List users
[**IssueToken**](UsersApi.md#IssueToken) | **Post** /users/{username}/token | Issue a token
[**Login**](UsersApi.md#Login) | **Post** /users/{username}/login | Log into a user account (obtain JWT)
[**Logout**](UsersApi.md#Logout) | **Delete** /users/{username}/login | Log out of a user account (invalidate existing JWT&#39;s) 
[**ResetPassword**](UsersApi.md#ResetPassword) | **Put** /users/{username}/login | Reset password
[**UpdateUser**](UsersApi.md#UpdateUser) | **Patch** /users/{username} | Update a user by their username
[**ValidateToken**](UsersApi.md#ValidateToken) | **Get** /users/self/token | Validate a token
[**Verify**](UsersApi.md#Verify) | **Patch** /users/{username}/login | Verify email address



## CreateUser

> User CreateUser(ctx, optional)

Create a new user

A verification email will automatically be sent to the user's email address. Normally this just contains the raw JWT - setting `Accept` to contain `text/html` will send an email with a link to the configured UI service and the token. 

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
 **optional** | ***CreateUserOpts** | optional parameters | nil if no parameters

### Optional Parameters

Optional parameters are passed through a pointer to a CreateUserOpts struct


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **user** | [**optional.Interface of User**](User.md)| User to create | 

### Return type

[**User**](User.md)

### Authorization

[jwt_admin](../README.md#jwt_admin)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteUser

> User DeleteUser(ctx, username)

Delete a user by their username

Requires at least an expired user JWT. A valid admin JWT is required to delete a user other than `self`. 

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string**| User&#39;s username. Can be &#x60;self&#x60; to indicate the currently authenticated user.  | 

### Return type

[**User**](User.md)

### Authorization

[jwt](../README.md#jwt), [jwt_admin](../README.md#jwt_admin)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetUser

> User GetUser(ctx, username)

Get a user by their username

Requires at least an expired user JWT. A valid admin JWT is required to retrieve a user other than `self`. 

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string**| User&#39;s username. Can be &#x60;self&#x60; to indicate the currently authenticated user.  | 

### Return type

[**User**](User.md)

### Authorization

[jwt](../README.md#jwt), [jwt_admin](../README.md#jwt_admin)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetUsers

> []User GetUsers(ctx, )

List users

### Required Parameters

This endpoint does not need any parameter.

### Return type

[**[]User**](User.md)

### Authorization

[jwt_admin](../README.md#jwt_admin)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## IssueToken

> TokenResponse IssueToken(ctx, username, optional)

Issue a token

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string**| User&#39;s username. | 
 **optional** | ***IssueTokenOpts** | optional parameters | nil if no parameters

### Optional Parameters

Optional parameters are passed through a pointer to a IssueTokenOpts struct


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **issueTokenRequest** | [**optional.Interface of IssueTokenRequest**](IssueTokenRequest.md)|  | 

### Return type

[**TokenResponse**](TokenResponse.md)

### Authorization

[jwt_admin](../README.md#jwt_admin)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## Login

> TokenResponse Login(ctx, username, optional)

Log into a user account (obtain JWT)

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string**| User&#39;s username. | 
 **optional** | ***LoginOpts** | optional parameters | nil if no parameters

### Optional Parameters

Optional parameters are passed through a pointer to a LoginOpts struct


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **loginRequest** | [**optional.Interface of LoginRequest**](LoginRequest.md)|  | 

### Return type

[**TokenResponse**](TokenResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## Logout

> Logout(ctx, username)

Log out of a user account (invalidate existing JWT's) 

Requires at least an expired user JWT. A valid admin JWT is required to logout a user other than `self`. 

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string**| User&#39;s username. Can be &#x60;self&#x60; to indicate the currently authenticated user.  | 

### Return type

 (empty response body)

### Authorization

[jwt](../README.md#jwt), [jwt_admin](../README.md#jwt_admin)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ResetPassword

> ResetPassword(ctx, username, optional)

Reset password

Making a request without a token (or request body) will generate a token and send it to the user's email address. Normally this just contains the raw JWT - setting `Accept` to contain `text/html` will send an email with a link to the configured UI service and the token. Passing the returned token to this endpoint (along with the new password) will perform the reset. 

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string**| User&#39;s username. Can be &#x60;self&#x60; to indicate the currently authenticated user.  | 
 **optional** | ***ResetPasswordOpts** | optional parameters | nil if no parameters

### Optional Parameters

Optional parameters are passed through a pointer to a ResetPasswordOpts struct


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **resetPasswordRequest** | [**optional.Interface of ResetPasswordRequest**](ResetPasswordRequest.md)|  | 

### Return type

 (empty response body)

### Authorization

[jwt_reset](../README.md#jwt_reset)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateUser

> User UpdateUser(ctx, username, optional)

Update a user by their username

Requires at least an expired user JWT. A valid admin JWT is required to update admin-only fields and modify a user other than `self`.  A verification email will automatically be sent to the user's email address if it has been changed. Normally this just contains the raw JWT - setting `Accept` to contain `text/html` will send an email with a link to the configured UI service and the token. 

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string**| User&#39;s username. Can be &#x60;self&#x60; to indicate the currently authenticated user.  | 
 **optional** | ***UpdateUserOpts** | optional parameters | nil if no parameters

### Optional Parameters

Optional parameters are passed through a pointer to a UpdateUserOpts struct


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **user** | [**optional.Interface of User**](User.md)| Partial user containing fields to update | 

### Return type

[**User**](User.md)

### Authorization

[jwt](../README.md#jwt), [jwt_admin](../README.md#jwt_admin)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ValidateToken

> ValidateToken(ctx, )

Validate a token

### Required Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[jwt](../README.md#jwt), [jwt_admin](../README.md#jwt_admin)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## Verify

> Verify(ctx, username)

Verify email address

Making a request without a token will generate a token and send it to the user's email address. Normally this just contains the raw JWT - setting `Accept` to contain `text/html` will send an email with a link to the configured UI service and the token. Passing the returned token to this endpoint will perform the verification. 

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string**| User&#39;s username. Can be &#x60;self&#x60; to indicate the currently authenticated user.  | 

### Return type

 (empty response body)

### Authorization

[jwt_verify](../README.md#jwt_verify)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

