# REST API

# Models
## User

```json5
{
    // Unique DB ID
    "id": 39,
    // Unique email address (must be `@tcd.ie`)
    "email": "asd@tcd.ie",
    // Unique username (must be a valid DNS name)
    "username": "test",
    // Stored internally as a bcrypt hash (must be at least 8 characters)
    "password": "$2a$10$ZAZTChzySdi5x3Ht9kV82Oy47kFdLV.G1Ae.st5P5lkQXikhfDtPu",
    "first_name": "Dude",
    "last_name": "Bro",
    "is_admin": false,
    "meta": {
        // Always ISO dates :P
        "created": "2020-09-15T15:31:18.868564Z",
        "updated": "2020-09-15T15:31:18.868564Z"
    }
}
```

# Errors
In an error scenario, an endpoint will return an appropriate 4XX (client error) or 5XX (server error) HTTP status, along
with a JSON object containing a `message` string for display to a user. Additional fields _may_ be provided.

# Endpoints

## `/v1/users`
### GET
List users.

Response: HTTP 200 body with array of users.

### POST
Create a new user.

Request: A complete user object. All fields (except for `meta` and `id`, which are ignored, and `password` are
required). A missing password will prevent a user from logging in.

Response: HTTP 201 body with new user.

Errors:
 - Validation error (e.g. User with username already exists, HTTP 400)

## `/v1/users/<username>`
### GET
Get user by username.

Response: HTTP 200 body with user.

Errors:
 - User with username does not exist (HTTP 404)

### DELETE
Delete a user by username

Response: HTTP 200 body with deleted user.

Errors:
 - User with username does not exist (HTTP 404)

### PATCH

Errors:
 - Validation error (e.g. User with username already exists, HTTP 400)
 - User with username does not exist (HTTP 404)
