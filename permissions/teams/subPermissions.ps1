#####################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-SubPermissions-Teams
# Grants/revokes teams dynamically based on person or contract data
# PowerShell V2
#####################################################
# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($actionContext.Configuration.isDebug) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{ }
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

#region functions
function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function Get-SanitizedGroupName {
    # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
    # This list of special characters includes: a leading space a trailing space and any of the following characters: # , + " \ < > 
    # A group account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
    # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
    # https://www.ietf.org/rfc/rfc2253.txt    
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim()
    $newName = $newName -replace " - ", "_"
    $newName = $newName -replace "[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,',`",,:,\,|,},{,.]", ""
    $newName = $newName -replace "\[", ""
    $newName = $newName -replace "]", ""
    $newName = $newName -replace " ", "_"
    $newName = $newName -replace "\.\.\.\.\.", "."
    $newName = $newName -replace "\.\.\.\.", "."
    $newName = $newName -replace "\.\.\.", "."
    $newName = $newName -replace "\.\.", "."

    # Remove diacritics
    $newName = Remove-StringLatinCharacters $newName
    
    return $newName
}
function Convert-StringToBoolean($obj) {
    if ($obj -is [PSCustomObject]) {
        foreach ($property in $obj.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string]) {
                $lowercaseValue = $value.ToLower()
                if ($lowercaseValue -eq "true") {
                    $obj.$($property.Name) = $true
                }
                elseif ($lowercaseValue -eq "false") {
                    $obj.$($property.Name) = $false
                }
            }
            elseif ($value -is [PSCustomObject] -or $value -is [System.Collections.IDictionary]) {
                $obj.$($property.Name) = Convert-StringToBoolean $value
            }
            elseif ($value -is [System.Collections.IList]) {
                for ($i = 0; $i -lt $value.Count; $i++) {
                    $value[$i] = Convert-StringToBoolean $value[$i]
                }
                $obj.$($property.Name) = $value
            }
        }
    }
    return $obj
}

function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $httpErrorObj.FriendlyMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $httpErrorObj.FriendlyMessage = $httpErrorObj.FriendlyMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.error
                }
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
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
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        throw $_
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
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.Powershell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

#region Get Access Token
try {
    #region Verify account reference
    $actionMessage = "verifying account reference"
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }
    #endregion Verify account reference

    #region Create authorization headers
    $actionMessage = "creating authorization headers"

    $authorizationHeadersSplatParams = @{
        TenantId     = $actionContext.Configuration.TenantID
        ClientId     = $actionContext.Configuration.AppId
        ClientSecret = $actionContext.Configuration.AppSecret
    }

    $headers = New-AuthorizationHeaders @authorizationHeadersSplatParams

    Write-Verbose "Created authorization headers. Result: $($headers | ConvertTo-Json)"
    #endregion Create authorization headers

    #region Define desired permissions
    try {
        $desiredPermissions = @{}
        if (-Not($actionContext.Operation -eq "revoke")) {
            # Example: Contract Based Logic:
            foreach ($contract in $personContext.Person.Contracts) {
                Write-Information "Contract: $($contract.ExternalId). In condition: $($contract.Context.InConditions)"
                if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $true)) {
                    # Example: department_<departmentname>
                    $teamName = "department_" + $contract.Department.DisplayName

                    # Example: title_<titlename>
                    # $teamName = "title_" + $contract.Title.Name

                    # Sanitize team name, e.g. replace " - " with "_" or other sanitization actions 
                    $teamName = Get-SanitizedGroupName -Name $teamName

                    # Get team to use objectGuid to avoid name change issues
                    $filter = "displayName+eq+'$($teamName)' & resourceProvisioningOptions/Any(x:x eq 'Team')"
                    Write-Verbose "Querying Microsoft Entra ID team that matches filter [$($filter)]"

                    $baseUri = "https://graph.microsoft.com/"
                    $splatWebRequest = @{
                        Uri     = "$baseUri/v1.0/groups?`$filter=$($filter)"
                        Headers = $headers
                        Method  = "GET"
                    }
                    $team = $null
                    $teamResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
                    $team = $teamResponse.Value
    
                    if ($team.Id.count -eq 0) {
                        throw "No team found that matches filter [$($filter)]"
                    }
                    elseif ($team.Id.count -gt 1) {
                        Throw  "Multiple teams found that matches filter [$($filter)]. Please correct this so the teams are unique."
                    }
                    else {
                        # Add team to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                        $desiredPermissions["$($team.id)"] = $team.displayName
                    }
                }
            }
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
    #endregion Define desired permissions
    
    Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))
    Write-Warning ("Existing Permissions: {0}" -f ($actionContext.CurrentPermissions.DisplayName | ConvertTo-Json))

    #region Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) {    
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No permissions defined") {
            #region Revoke permission from account
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0&tabs=http
            $actionMessage = "revoking team [$($permission.Value)] with id [$($permission.Name)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            $baseUri = "https://graph.microsoft.com/"
            $revokePermissionSplatParams = @{
                Uri         = "$($baseUri)/v1.0/groups/$($permission.Name)/members/$($actionContext.References.Account)/`$ref"
                Headers     = $headers
                Method      = "DELETE"
                Verbose     = $false
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                Write-Verbose "SplatParams: $($revokePermissionSplatParams | ConvertTo-Json)"

                $revokedPermission = Invoke-RestMethod @revokePermissionSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Revoked team [$($permission.Value)] with id [$($permission.Name)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would revoke team [$($permission.Value)] with id [$($permission.Name)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Revoke permission from account
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }
    #endregion Compare current with desired permissions and revoke permissions

    #region Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })
    
        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            #region Grant permission to account
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
            $actionMessage = "granting team [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            $grantPermissionBody = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)"
            }
            
            $baseUri = "https://graph.microsoft.com/"
            $grantPermissionSplatParams = @{
                Uri         = "$($baseUri)/v1.0/groups/$($permission.Name)/members/$($actionContext.References.Account)/`$ref"
                Headers     = $headers
                Method      = "POST"
                Body        = ($grantPermissionBody | ConvertTo-Json -Depth 10)
                Verbose     = $false
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                Write-Verbose "SplatParams: $($grantPermissionSplatParams | ConvertTo-Json)"

                $grantedPermission = Invoke-RestMethod @grantPermissionSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "Granted team [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would grant team [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Grant permission to account
        }    
    }
    #endregion Compare desired with current permissions and grant permissions
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or
        $($ex.Exception.GetType().FullName -eq "System.Net.WebException")) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    
    if ($auditMessage -like "*Error code: Request_ResourceNotFound*" -and $auditMessage -like "*$($actionContext.References.Permission.id)*") {
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission"
                Message = "Skipped revoking team [$($permission.Value)] with id [$($permission.Name)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: User is already no longer a member or the team no longer exists."
                IsError = $false
            })
    }
    elseif ($auditMessage -like "*One or more added object references already exist for the following modified properties: 'members'*") {
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "Skipped granting team [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: User is already a member of the team."
                IsError = $false
            })
    }
    else {
        Write-Warning $warningMessage
    
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })
    }
}
finally { 
    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $outputContext.SubPermissions.count -eq 0) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "No permissions defined"
                Reference   = [PSCustomObject]@{ Id = "No permissions defined" }
            })

        Write-Warning "Skipped granting permissions for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No permissions defined."
    }

    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}
