# Go API client for iam

API for managing and authenticating Netsoc users.


## Overview
This API client was generated by the [OpenAPI Generator](https://openapi-generator.tech) project.  By using the [OpenAPI-spec](https://www.openapis.org/) from a remote server, you can easily generate an API client.

- API version: 1.0.11
- Package version: 1.0.0
- Build package: org.openapitools.codegen.languages.GoClientCodegen

## Installation

Install the following dependencies:

```shell
go get github.com/stretchr/testify/assert
go get golang.org/x/oauth2
go get golang.org/x/net/context
go get github.com/antihax/optional
```

Put the package under your project folder and add the following in import:

```golang
import "./iam"
```

## Documentation for API Endpoints

All URIs are relative to *https://iam.netsoc.ie/v1*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*UsersApi* | [**CreateUser**](docs/UsersApi.md#createuser) | **Post** /users | Create a new user
*UsersApi* | [**DeleteUser**](docs/UsersApi.md#deleteuser) | **Delete** /users/{username} | Delete a user by their username
*UsersApi* | [**GetUser**](docs/UsersApi.md#getuser) | **Get** /users/{username} | Get a user by their username
*UsersApi* | [**GetUserByID**](docs/UsersApi.md#getuserbyid) | **Get** /users/id:{uid} | Get a user by their ID
*UsersApi* | [**GetUsers**](docs/UsersApi.md#getusers) | **Get** /users | List users
*UsersApi* | [**IssueToken**](docs/UsersApi.md#issuetoken) | **Post** /users/{username}/token | Issue a token
*UsersApi* | [**Login**](docs/UsersApi.md#login) | **Post** /users/{username}/login | Log into a user account (obtain JWT)
*UsersApi* | [**Logout**](docs/UsersApi.md#logout) | **Delete** /users/{username}/login | Log out of a user account (invalidate existing JWT&#39;s) 
*UsersApi* | [**ResetPassword**](docs/UsersApi.md#resetpassword) | **Put** /users/{username}/login | Reset password
*UsersApi* | [**UpdateUser**](docs/UsersApi.md#updateuser) | **Patch** /users/{username} | Update a user by their username
*UsersApi* | [**ValidateToken**](docs/UsersApi.md#validatetoken) | **Get** /users/self/token | Validate a token
*UsersApi* | [**Verify**](docs/UsersApi.md#verify) | **Patch** /users/{username}/login | Verify email address


## Documentation For Models

 - [Error](docs/Error.md)
 - [IssueTokenRequest](docs/IssueTokenRequest.md)
 - [LoginRequest](docs/LoginRequest.md)
 - [ResetPasswordRequest](docs/ResetPasswordRequest.md)
 - [TokenResponse](docs/TokenResponse.md)
 - [User](docs/User.md)
 - [UserMeta](docs/UserMeta.md)


## Documentation For Authorization



## jwt

- **Type**: HTTP basic authentication

Example

```golang
auth := context.WithValue(context.Background(), sw.ContextBasicAuth, sw.BasicAuth{
    UserName: "username",
    Password: "password",
})
r, err := client.Service.Operation(auth, args)
```


## jwt_admin

- **Type**: HTTP basic authentication

Example

```golang
auth := context.WithValue(context.Background(), sw.ContextBasicAuth, sw.BasicAuth{
    UserName: "username",
    Password: "password",
})
r, err := client.Service.Operation(auth, args)
```


## jwt_reset

- **Type**: HTTP basic authentication

Example

```golang
auth := context.WithValue(context.Background(), sw.ContextBasicAuth, sw.BasicAuth{
    UserName: "username",
    Password: "password",
})
r, err := client.Service.Operation(auth, args)
```


## jwt_verify

- **Type**: HTTP basic authentication

Example

```golang
auth := context.WithValue(context.Background(), sw.ContextBasicAuth, sw.BasicAuth{
    UserName: "username",
    Password: "password",
})
r, err := client.Service.Operation(auth, args)
```



## Author



