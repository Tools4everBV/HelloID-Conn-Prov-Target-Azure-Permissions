
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Microsoft-Entra-ID/blob/main/Logo.png?raw=true">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Microsoft-Entra-ID](#helloid-conn-prov-target-microsoft-entra-id)
  - [Table of contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Remarks](#remarks)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Provisioning PowerShell V2 connector](#provisioning-powershell-v2-connector)
      - [Correlation configuration](#correlation-configuration)
      - [Field mapping](#field-mapping)
    - [Connection settings](#connection-settings)
  - [Setup the connector](#setup-the-connector)
    - [Application Registration](#application-registration)
    - [Configuring App Permissions](#configuring-app-permissions)
    - [Authentication and Authorization](#authentication-and-authorization)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Prerequisites
- [ ] _HelloID_ Provisioning agent (cloud or on-prem).
- [ ] _HelloID_ environment.
- [ ] Registered App Registration in Microsoft Entra ID. The following values are needed to connect:
  - [ ] Tenant ID.
  - [ ] Client ID.
  - [ ] Client Secret.

## Remarks
- The script for dynamically managing permissions in Teams closely resembles that for Groups, with the only distinction being an added filter for Teams-enabled groups. This is because a Team is inherently an M365 group, allowing us to manage its members within the group context rather than within Teams itself.
- Currently, the [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0) exclusively supports Microsoft 365 and Security groups. Consequently, Mail-enabled security groups and Distribution groups cannot be managed via this API. To manage these types of groups, utilize the [Exchange Online connector](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-ExchangeOnline).
- This connector provides the functionality to create Guest accounts through invitation, allowing users to log in using their invited email addresses. This feature can be enabled or disabled using the "Invite as Guest" option.
If direct creation of Microsoft Entra ID Guest accounts (with login names under the tenant domain) is preferred, ensure that the "Invite as Guest" option is not enabled.
By specifying the userType as 'Guest' in the mapping, Guest accounts with login names under the tenant domain can be effortlessly created.

## Introduction
_HelloID-Conn-Prov-Target-Microsoft-Entra-ID_ is a _target_ connector. _Microsoft_ provides a set of REST API's that allow you to programmatically interact with its data. The Microsoft Entra ID connector uses the API endpoints listed in the table below.

| Endpoint                                                                                                                                                        | Description                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| [/v1.0/users/{id}](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http)                                                          | Get a user (GET)                           |
| [/v1.0/users](https://learn.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0&tabs=http)                                                        | Create user (POST)                         |
| [/v1.0/users/{id}](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http)                                                       | Update user (PATCH)                        |
| [/v1.0/users/{id}](https://learn.microsoft.com/en-us/graph/api/user-delete?view=graph-rest-1.0&tabs=http)                                                       | Delete user (DELETE)                       |
| [/v1/groups](https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http)                                                              | List groups (GET)                          |
| [/v1/groups/{group-id}/members/$ref](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http)                              | Add member (POST)                          |
| [/v1/groups/{id}/members/{id}/$ref](https://learn.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0&tabs=http)                             | Remove member (DELETE)                     |
| [/v1/groups](https://learn.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http)                                                       | Create group (POST)                        |
| [/v1.0/users/{id}/authentication/emailMethods/{id}](https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-get?view=graph-rest-1.0&tabs=http)    | Get emailAuthenticationMethod (GET)        |
| [/v1.0/users/{id}/authentication/emailMethods](https://learn.microsoft.com/nl-nl/graph/api/authentication-post-emailmethods?view=graph-rest-1.0&tabs=http)      | Create emailMethod (POST)                  |
| [/v1.0/users/{id}/authentication/emailMethods/{id}](https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-update?view=graph-rest-1.0&tabs=http) | Update emailAuthenticationMethod (PATCH)   |
| [/v1.0/users/{id}/authentication/emailMethods/{id}](https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-delete?view=graph-rest-1.0&tabs=http) | UDelete emailAuthenticationMethod (DELETE) |
| [/v1.0/users/{id}/authentication/phoneMethods/{id}](https://learn.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-get?view=graph-rest-1.0&tabs=http)    | Get phoneAuthenticationMethod (GET)        |
| [/v1.0/users/{id}/authentication/phoneMethods](https://learn.microsoft.com/nl-nl/graph/api/authentication-post-phonemethods?view=graph-rest-1.0&tabs=http)      | Create phoneMethod (POST)                  |
| [/v1.0/users/{id}/authentication/phoneMethods/{id}](https://learn.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-update?view=graph-rest-1.0&tabs=http) | Update phoneAuthenticationMethod (PATCH)   |
| [/v1.0/users/{id}/authentication/phoneMethods/{id}](https://learn.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-delete?view=graph-rest-1.0&tabs=http) | UDelete phoneAuthenticationMethod (DELETE) |


The following lifecycle actions are available:

| Action                                            | Description                                                                                |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| create.ps1                                        | Create or correlate to an account                                                          |
| delete.ps1                                        | Delete an account                                                                          |
| disable.ps1                                       | Disable an account                                                                         |
| enable.ps1                                        | Enable an account                                                                          |
| update.ps1                                        | Update an account                                                                          |
| uniquenessCheck.json                              | Default _uniquenessCheck.json_                                                             |
| groups - permissions.ps1                          | List groups as permissions                                                                 |
| groups - grantPermission.ps1                      | Grant groupmembership to an account                                                        |
| groups - revokePermission.ps1                     | Revoke groupmembership from an account                                                     |
| groups - resources.ps1                            | Create groups from resources                                                               |
| groups - subPermissions.ps1                       | Grant/Revoke groupmembership from an account                                               |
| emailAuthenticationMethods - permissions.ps1      | List emailAuthenticationMethods as permissions                                             |
| emailAuthenticationMethods - grantPermission.ps1  | Grant emailAuthenticationMethod to an account                                              |
| emailAuthenticationMethods - revokePermission.ps1 | Revoke emailAuthenticationMethod from an account                                           |
| emailAuthenticationMethods - configuration.json   | Additional _configuration.json_ with settings specifically for emailAuthenticationMethods  |
| phoneAuthenticationMethods - permissions.ps1      | List phoneAuthenticationMethods as permissions                                             |
| phoneAuthenticationMethods - grantPermission.ps1  | Grant phoneAuthenticationMethod to an account                                              |
| phoneAuthenticationMethods - revokePermission.ps1 | Revoke phoneAuthenticationMethod from an account                                           |
| phoneAuthenticationMethods - configuration.json   | Additional _configuration.json_ with settings specifically for phoneAuthenticationMethods  |
| configuration.json                                | Default _configuration.json_                                                               |
| fieldMapping.json                                 | _fieldMapping.json_ for when using the the full account lifecycle                          |
| fieldMapping.correlateOnly.json                   | _fieldMapping.json_ for when only using the correlation and not the full account lifecycle |

## Getting started
By using this connector you will have the ability to seamlessly create and user accounts and groups in Microsoft Entra ID. Additionally, you can set the MFA phone or email settings.

Connecting to Microsoft the Microsoft Graph API is straightforward. Simply utilize the API Key and API Secret pair.
For further details, refer to the following pages in the Microsoft Docs:

[Use the Microsoft Graph API](https://learn.microsoft.com/en-us/graph/use-the-api).
[User Properties](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties).
[Supported User Properties for Correlation](https://learn.microsoft.com/en-us/graph/aad-advanced-queries?tabs=http#user-properties).

### Provisioning PowerShell V2 connector

#### Correlation configuration
The correlation configuration is used to specify which properties will be used to match an existing account within _Microsoft Entra ID_ to a person in _HelloID_.

To properly setup the correlation:

1. Open the `Correlation` tab.

2. Specify the following configuration:

    | Setting                   | Value      |
    | ------------------------- | ---------- |
    | Enable correlation        | `True`     |
    | Person correlation field  | ``         |
    | Account correlation field | `UserName` |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

#### Field mapping
The field mapping can be imported by using the _fieldMapping.json_ file.

### Connection settings
The following settings are required to connect to the API.

| Setting                                  | Description                                                                                                                  | Mandatory |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --------- |
| App Registration Directory (tenant) ID   | The ID to the Tenant in Microsoft Entra ID                                                                                   | Yes       |
| App Registration Application (client) ID | The ID to the App Registration in Microsoft Entra ID                                                                         | Yes       |
| App Registration Client Secret           | The Client Secret to the App Registration in Microsoft Entra ID                                                              | Yes       |
| Correlate only                           | When toggled, this connector will only correlate to an existing account and skip all further account lifecycle actions.      | No        |
| IsDebug                                  | When toggled, extra logging is shown. Note that this is only meant for debugging, please switch this off when in production. | No        |


## Setup the connector
### Application Registration
The first step to connect to Graph API and make requests, is to register a new **Microsoft Entra ID Application**. The application is used to connect to the API and to manage permissions.

- Navigate to **App Registrations** in Microsoft Entra ID, and select “New Registration” (**Microsoft Entra ID Portal > Microsoft Entra ID > App Registration > New Application Registration**).
- Next, give the application a name. In this example we are using “**HelloID PowerShell**” as application name.
- Specify who can use this application (**Accounts in this organizational directory only**).
- Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
- Click the “**Register**” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to **Microsoft Entra ID Portal > Microsoft Entra ID >App Registrations**.
Select the application we created before, and select “**API Permissions**” or “**View API Permissions**”.
To assign a new permission to your application, click the “Add a permission” button.
From the “**Request API Permissions**” screen click “**Microsoft Graph**”.
For this connector the following permissions are used as **Application permissions**:
-	Read and Write all user’s full profiles by using *User.ReadWrite.All*
-	Read and Write all groups in an organization’s directory by using *Group.ReadWrite.All*
-	Read and write all group memberships by using *GroupMember.ReadWrite.All*
-	Read and write all users' authentication methods by using *UserAuthenticationMethod.ReadWrite.All*

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “**Grant admin consent for TENANT**” button.

### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

-	First we need to get the **Client ID**, go to the **Microsoft Entra ID Portal > Microsoft Entra ID > App Registrations**.
-	Select your application and copy the Application (client) ID value.
-	After we have the Client ID we also have to create a **Client Secret**.
-	From the Microsoft Entra ID Portal, go to **Microsoft Entra ID > App Registrations**.
-	Select the application we have created before, and select "**Certificates and Secrets**". 
-	Under “Client Secrets” click on the “**New Client Secret**” button to create a new secret.
-	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
-	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
-	At last we need to get the **Tenant ID**. This can be found in the Microsoft Entra ID Portal by going to **Microsoft Entra ID > Overview**.

## Getting help
> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
