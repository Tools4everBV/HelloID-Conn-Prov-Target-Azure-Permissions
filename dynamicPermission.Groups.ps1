#####################################################
# HelloID-Conn-Prov-Target-AzureActiveDirectory-DynamicPermissions-Groups
#
# Version: 2.0.0 | new-powershell-connector
#####################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# The accountReference object contains the Identification object provided in the create account call
$aRef = $actionContext.References.Account 

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false 

# Set debug logging
switch ($($actionContext.Configuration.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

# Used to connect to Azure AD Graph API
$AADtenantID = $actionContext.Configuration.AADtenantID
$AADAppId = $actionContext.Configuration.AADAppId
$AADAppSecret = $actionContext.Configuration.AADAppSecret

$currentPermissions = @{}
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

#region functions
function Get-ADSanitizeGroupName {
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim()
    # $newName = $newName -replace ' - ','_'
    $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",,:,\,|,},{,.]', ''
    $newName = $newName -replace '\[', ''
    $newName = $newName -replace ']', ''
    # $newName = $newName -replace ' ','_'
    $newName = $newName -replace '\.\.\.\.\.', '.'
    $newName = $newName -replace '\.\.\.\.', '.'
    $newName = $newName -replace '\.\.\.', '.'
    $newName = $newName -replace '\.\.', '.'
    return $newName
}

function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$TenantId/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')

        Write-Output $headers  
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}

function Resolve-MicrosoftGraphAPIErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $errorMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $errorMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $errorMessage = $errorMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $errorMessage = $errorObjectConverted.error
                }
            }
            else {
                $errorMessage = $ErrorObject
            }
        }
        catch {
            $errorMessage = $ErrorObject
        }

        Write-Output $errorMessage
    }
}
#endregion functions

#region Get Access Token
try {
    try {
        $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret
    }
    catch {
        # Clean up error variables
        $verboseErrorMessage = $null
        $auditErrorMessage = $null

        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex

            $verboseErrorMessage = $errorObject.ErrorMessage

            $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }

        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "GrantDynamicPermission"
                Message = "Error creating Access Token. Error Message: $auditErrorMessage"
                IsError = $true
            })

        throw "Error creating Access Token. Error Message: $auditErrorMessage"
    }
    #endregion Get Access Token

    try {
        #region Change mapping here
        $desiredPermissions = @{}
        if (-Not($actionContext.Operation -eq "revoke")) {
            # Example: Contract Based Logic:
            foreach ($contract in $personContext.Person.Contracts) {
                Write-Verbose ("Contract in condition: {0}" -f $contract.Context.InConditions)
                if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $true)) {
                    # Example: department_<departmentname>
                    $groupName = "department_" + $contract.Department.DisplayName

                    # Example: title_<titlename>
                    # $groupName = "title_" + $contract.Title.Name

                    # Sanitize group name, e.g. replace ' - ' with '_' or other sanitization actions 
                    $groupName = Get-ADSanitizeGroupName -Name $groupName
            
                    # Get group to use objectGuid to avoid name change issues
                    $filter = "displayName+eq+'$($groupName)'"
                    Write-Verbose "Querying Azure AD group that matches filter '$($filter)'"

                    $baseUri = "https://graph.microsoft.com/"
                    $splatWebRequest = @{
                        Uri     = "$baseUri/v1.0/groups?`$filter=$($filter)"
                        Headers = $headers
                        Method  = 'GET'
                    }
                    $group = $null
                    $groupResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
                    $group = $groupResponse.Value
    
                    if ($group.Id.count -eq 0) {
                        Throw "No Group found that matches filter '$($filter)'"
                    }
                    elseif ($group.Id.count -gt 1) {
                        Throw  "Multiple Groups found that matches filter '$($filter)'. Please correct this so the groups are unique."
                    }

                    # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                    $desiredPermissions["$($group.id)"] = $group.displayName
                }
            }
    
            # Example: Person Based Logic:
            # Example: location_<locationname>
            # $groupName = "location_" + $p.Location.Name

            # # Sanitize group name, e.g. replace ' - ' with '_' or other sanitization actions 
            # $groupName = Get-ADSanitizeGroupName -Name $groupName
    
            # # Get group to use objectGuid to avoid name change issues
            # $filter = "displayName+eq+'$($groupName)'"
            # Write-Verbose "Querying Azure AD group that matches filter '$($filter)'"

            # $baseUri = "https://graph.microsoft.com/"
            # $splatWebRequest = @{
            #     Uri     = "$baseUri/v1.0/groups?`$filter=$($filter)"
            #     Headers = $headers
            #     Method  = 'GET'
            # }
            # $group = $null
            # $groupResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
            # $group = $groupResponse.Value

            # if ($group.Id.count -eq 0) {
            #     Write-Error "No Group found that matches filter '$($filter)'"
            # }
            # elseif ($group.Id.count -gt 1) {
            #     Write-Error "Multiple Groups found that matches filter '$($filter)'. Please correct this so the groups are unique."
            # }

            # # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
            # $desiredPermissions["$($group.id)"] = $group.displayName
        }
    }
    catch {
        $ex = $PSItem      
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "GrantDynamicPermission"
                Message = "$($ex.Exception.Message)"
                IsError = $true
            })
        throw $_
    }
    



    Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))

    Write-Warning ("Existing Permissions: {0}" -f ($actionContext.CurrentPermissions.DisplayName | ConvertTo-Json))
    #endregion Change mapping here

    #region Execute

    # Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            # Grant AzureAD Groupmembership
            try {
                Write-Verbose "Granting permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
    
                $bodyAddPermission = [PSCustomObject]@{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($aRef)"
                }
                $body = ($bodyAddPermission | ConvertTo-Json -Depth 10)
    
                $baseUri = "https://graph.microsoft.com/"
                $splatWebRequest = @{
                    Uri     = "$baseUri/v1.0/groups/$($permission.Name)/members/`$ref"
                    Headers = $headers
                    Method  = 'POST'
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
                }
                
                if (-Not($actionContext.DryRun -eq $true)) {
                    $addPermission = Invoke-RestMethod @splatWebRequest -Verbose:$false
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantDynamicPermission"
                            Message = "Successfully granted permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would grant permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                }
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null
    
                $ex = $PSItem
                if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                    $errorObject = Resolve-HTTPError -Error $ex
            
                    $verboseErrorMessage = $errorObject.ErrorMessage
            
                    $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
                }
            
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }
            
                Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
                
                # Since the error message for adding a user that is already member is a 400 (bad request), we cannot check on a code or type
                # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
                if ($auditErrorMessage -like "*One or more added object references already exist for the following modified properties*") {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantDynamicPermission"
                            Message = "User '$($aRef)' is already a member of the group '$($permission.Value)'. Skipped grant of permission to group '$($permission.Value) ($($permission.Name))' for user '$($aRef)'"
                            IsError = $false
                        }
                    )
                }
                else {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantDynamicPermission"
                            Message = "Error granting permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'. Error Message: $auditErrorMessage"
                            IsError = $true
                        })
                }
            }
        }    
    }

    # Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) {    
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No Groups Defined") {
            # Revoke AzureAD Groupmembership
            try {
                Write-Verbose "Revoking permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
    
                $baseUri = "https://graph.microsoft.com/"
                $splatWebRequest = @{
                    Uri     = "$baseUri/v1.0/groups/$($permission.Name)/members/$($aRef)/`$ref"
                    Headers = $headers
                    Method  = 'DELETE'
                }
                Write-Warning ($splatWebRequest | Out-String)
    
                if (-Not($actionContext.DryRun -eq $true)) {
                    $removePermission = Invoke-RestMethod @splatWebRequest -Verbose:$false
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "RevokeDynamicPermission"
                            Message = "Successfully revoked permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would revoke permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                }
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null
    
                $ex = $PSItem
                if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                    $errorObject = Resolve-HTTPError -Error $ex
            
                    $verboseErrorMessage = $errorObject.ErrorMessage
            
                    $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
                }
            
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

                if ($auditErrorMessage -like "*Error code: Request_ResourceNotFound*" -and $auditErrorMessage -like "*$($permission.Name)*") {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "RevokeDynamicPermission"
                            Message = "Membership to group '$($permission.Value)' for user '$($aRef)' couldn't be found. User is already no longer a member or the group no longer exists. Skipped revoke of permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                            IsError = $false
                        })
                }
                else {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "RevokeDynamicPermission"
                            Message = "Error revoking permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'. Error Message: $auditErrorMessage"
                            IsError = $true
                        })
                }
            }
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }

    # Update current permissions
    # # Warning! This example will grant all permissions again! Only uncomment this when this is needed (e.g. force update)
    # if ($o -eq "update") {
    #     # Grant all desired permissions, ignoring current permissions
    #     foreach ($permission in $desiredPermissions.GetEnumerator()) {
    #         $subPermissions.Add([PSCustomObject]@{
    #                 DisplayName = $permission.Value
    #                 Reference   = [PSCustomObject]@{ Id = $permission.Name }
    #             })

    #         # Grant AzureAD Groupmembership
    #         try {
    #             Write-Verbose "Granting permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
        
    #             $bodyAddPermission = [PSCustomObject]@{
    #                 "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($aRef)"
    #             }
    #             $body = ($bodyAddPermission | ConvertTo-Json -Depth 10)
        
    #             $splatWebRequest = @{
    #                 Uri     = "$baseUri/v1.0/groups/$($permission.Name)/members/`$ref"
    #                 Headers = $headers
    #                 Method  = 'POST'
    #                 Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
    #             }
        
    #             if (-Not($actionContext.DryRun -eq $true)) {
    #                 $addPermission = Invoke-RestMethod @splatWebRequest -Verbose:$false
    #                 $outputContext.AuditLogs.Add([PSCustomObject]@{
    #                         Action  = "UpdateDynamicPermission"
    #                         Message = "Successfully granted permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
    #                         IsError = $false
    #                     })
    #             }
    #             else {
    #                 Write-Warning "DryRun: Would grant permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
    #             }
    #         }
    #         catch {
    #             # Clean up error variables
    #             $verboseErrorMessage = $null
    #             $auditErrorMessage = $null
        
    #             $ex = $PSItem
    #             if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
    #                 $errorObject = Resolve-HTTPError -Error $ex
                
    #                 $verboseErrorMessage = $errorObject.ErrorMessage
                
    #                 $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
    #             }
                
    #             # If error message empty, fall back on $ex.Exception.Message
    #             if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
    #                 $verboseErrorMessage = $ex.Exception.Message
    #             }
    #             if ([String]::IsNullOrEmpty($auditErrorMessage)) {
    #                 $auditErrorMessage = $ex.Exception.Message
    #             }
                
    #             Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
                    
    #             # Since the error message for adding a user that is already member is a 400 (bad request), we cannot check on a code or type
    #             # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
    #             if ($auditErrorMessage -like "*One or more added object references already exist for the following modified properties*") {
    #                 $outputContext.AuditLogs.Add([PSCustomObject]@{
    #                         Action  = "UpdateDynamicPermission"
    #                         Message = "User '$($aRef)' is already a member of the group '$($permission.Value)'. Skipped grant of permission to group '$($permission.Value) ($($permission.Name))' for user '$($aRef)'"
    #                         IsError = $false
    #                     }
    #                 )
    #             }
    #             else {
    #                 $outputContext.AuditLogs.Add([PSCustomObject]@{
    #                         Action  = "UpdateDynamicPermission"
    #                         Message = "Error granting permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'. Error Message: $auditErrorMessage"
    #                         IsError = $True
    #                     })
    #             }
    #         }
    #     }    
    # }
}
#endregion Execute
catch {
    Write-Verbose $_
}
finally { 
    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $outputContext.SubPermissions.count -eq 0) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "No Groups Defined"
                Reference   = [PSCustomObject]@{ Id = "No Groups Defined" }
            })
    }
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}
