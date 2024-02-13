#####################################################
# HelloID-Conn-Prov-Target-AzureActiveDirectory-ResourceCreation-Groups
#
# Version: 2.0.0 | new-powershell-connector
#####################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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

#region functions
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

#region Execute
# In preview only the first 10 items of the SourceData are used
try {
    foreach ($resource in $resourceContext.SourceData) {
        Write-Verbose "Checking $($resource)"
        try {
            #region Change mapping here
            # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
            # This list of special characters includes: a leading space a trailing space and any of the following characters: # , + " \ < > 
            # A group account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
            # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
            # https://www.ietf.org/rfc/rfc2253.txt

            $groupType = "Microsoft 365 group"  # "Microsoft 365 group" or "Security group"
            $groupVisibility = "Public"

            # # Example: department_<departmentname> (department differs from other objects as the property for the name is "DisplayName", not "Name")
            $groupName = "department_" + "$($resource.DisplayName)"
            # Sanitize group name, e.g. replace ' - ' with '_' or other sanitization actions 
            $groupName = Get-ADSanitizeGroupName -Name $groupName

            $groupDescription = "Group for department " + "$($resource.DisplayName)"

            # Example: title_<titlename>
            # $groupName = "title_" + "$($resource.Name)"
            # Sanitize group name, e.g. replace ' - ' with '_' or other sanitization actions 
            # $groupName = Get-ADSanitizeGroupName -Name $groupName

            # $groupDescription = "Group for title " + "$($resource.Name)"

            # Example: customfield_ <customfield> (custom fields consists of only one attribute, no object with multiple attributes present!)
            # $groupName = "customfield_" + "$($resource)"
            # Sanitize group name, e.g. replace ' - ' with '_' or other sanitization actions 
            # $groupName = Get-ADSanitizeGroupName -Name $groupName

            # $groupDescription = "Group for custom field " + "$($resource)"
            #endregion Change mapping here

            $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret
            
            $filter = "displayName+eq+'$($groupName)'"
            Write-Verbose "Querying Azure AD group that matches filter '$($filter)'"

            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = "$baseUri/v1.0/groups?`$filter=$($filter)"
                Headers = $headers
                Method  = 'GET'
            }
            $currentGroup = $null
            $currentGroupResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
            $currentGroup = $currentGroupResponse.Value

            if ($null -eq $currentGroup.Id) {
                $groupExists = $false
            }
            else {
                $groupExists = $true
            }

            # If resource does not exist
            if ($groupExists -eq $False) {
                <# Resource creation preview uses a timeout of 30 seconds
                while actual run has timeout of 10 minutes #>
                Switch ($groupType) {
                    'Microsoft 365 group' {
                        $group = [PSCustomObject]@{
                            displayName     = $groupName
                            description     = $groupDescription
                            mailNickname    = $groupName.Replace(" ", "")
                            visibility      = $groupVisibility

                            groupTypes      = @("Unified") # Needs to be set to with 'Unified' to create Microsoft 365 group
                            mailEnabled     = $true # Needs to be enabled to create Microsoft 365 group
                            securityEnabled = $false # Needs to be disabled to create Microsoft 365 group

                            # allowExternalSenders = $allowExternalSenders - Not supported with Application permissions
                            # autoSubscribeNewMembers = $autoSubscribeNewMembers - Not supported with Application permissions
                        }
                    }

                    'Security group' {
                        $group = [PSCustomObject]@{
                            displayName     = $groupName
                            description     = $groupDescription
                            mailNickname    = $groupName.Replace(" ", "")
                            visibility      = $groupVisibility

                            #groupTypes = @("") # Needs to be empty to create Security group
                            mailEnabled     = $false # Needs to be disabled to create Security group
                            securityEnabled = $true # Needs to be enabled to create Security group

                            # allowExternalSenders = $allowExternalSenders - Not supported with Application permissions
                            # autoSubscribeNewMembers = $autoSubscribeNewMembers - Not supported with Application permissions                            
                        }
                    }
                }

                if (-Not($actionContext.DryRun -eq $True)) {
                    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

                    $body = $group | ConvertTo-Json -Depth 10
                    $baseUri = "https://graph.microsoft.com/"
                    $splatWebRequest = @{
                        Uri     = "$baseUri/v1.0/groups"
                        Headers = $headers
                        Method  = 'POST'
                        Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    }
                    $newGroup = $null
                    $newGroup = Invoke-RestMethod @splatWebRequest -Verbose:$false

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Created group: $($newGroup.displayName) ($($newGroup.Id))"
                            Action  = "CreateResource"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: would create group $($groupName): $($group | ConvertTo-Json)"
                }
            }
            else {
                if ($actionContext.DryRun -eq $True) {
                    Write-Warning "Group $($groupName) already exists"
                }

                # $outputContext.AuditLogs.Add([PSCustomObject]@{
                #     Message = "Skipped creation of group: $($newGroup.displayName) ($($newGroup.Id))"
                #     Action  = "CreateResource"
                #     IsError = $false
                # })
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

            Write-Warning "Failed to create group $($groupName): $($group | ConvertTo-Json). Error Message: $auditErrorMessage"

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Failed to create group $($groupName). Error Message: $auditErrorMessage"
                    Action  = "CreateResource"
                    IsError = $true
                })
        }
    }
}
#endregion Execute
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}