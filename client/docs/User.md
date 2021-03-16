# User

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Id** | **int32** | Unique database identifier, not modifiable. | 
**Username** | **string** | Unique username (must be a valid DNS name) | 
**Email** | **string** | Unique email address (must be &#x60;@tcd.ie&#x60;) | 
**Password** | Pointer to **string** | Stored internally as a bcrypt hash. If unset, login will be disabled.  | [optional] 
**FirstName** | **string** |  | 
**LastName** | **string** |  | 
**SshKey** | Pointer to **string** | SSH public key | [optional] 
**Verified** | Pointer to **bool** | Indicates if the user&#39;s email address is verified. Only modifiable directly by an admin. | [optional] [default to false]
**IsAdmin** | Pointer to **bool** | Indicates if the user is an admin. Only modifiable by an admin. | [optional] [default to false]
**Renewed** | [**time.Time**](time.Time.md) | Date and time when the user&#39;s membership was last renewed. Only modifiable by an admin.  | [optional] [default to 0001-01-01T00:00Z]
**Meta** | [**UserMeta**](UserMeta.md) |  | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


