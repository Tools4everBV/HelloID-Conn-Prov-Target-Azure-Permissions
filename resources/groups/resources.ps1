#####################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Resources-Groups
# Creates groups dynamically based on HR data
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

#region group
# Make sure the resourceContext data is unique. Fill in the required fields after -unique
# Example: department
$resourceData = $resourceContext.SourceData | Select-Object -Unique ExternalId, DisplayName
# Example: title
# $resourceData = $resourceContext.SourceData | Select-Object -Unique ExternalId, Name
# Define correlation
$correlationField = "displayName"
$correlationValue = "" # Defined later in script
#endRegion group

#region Get Access Token
try {
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

    #region Get Microsoft Entra ID Groups
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Groups"

    $microsoftEntraIDGroups = [System.Collections.ArrayList]@()
    do {
        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDGroupsSplatParams = @{
            Uri         = "$($baseUri)/v1.0/groups?`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDGroupsResult.'@odata.nextLink')) {
            $getMicrosoftEntraIDGroupsSplatParams["Uri"] = $getMicrosoftEntraIDGroupsResult.'@odata.nextLink'
        }

        $getMicrosoftEntraIDGroupsResult = $null
        $getMicrosoftEntraIDGroupsResult = Invoke-RestMethod @getMicrosoftEntraIDGroupsSplatParams
    
        if ($getMicrosoftEntraIDGroupsResult.Value -is [array]) {
            [void]$microsoftEntraIDGroups.AddRange($getMicrosoftEntraIDGroupsResult.Value)
        }
        else {
            [void]$microsoftEntraIDGroups.Add($getMicrosoftEntraIDGroupsResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDGroupsResult.'@odata.nextLink'))

    # Group on correlation property to check if group exists (as correlation property has to be unique for a group)
    $microsoftEntraIDGroupsGrouped = $microsoftEntraIDGroups | Group-Object $correlationField -AsHashTable -AsString

    Write-Information "Queried Microsoft Entra ID Groups. Result count: $(($microsoftEntraIDGroups | Measure-Object).Count)"
    #endregion Get Microsoft Entra ID Groups

    foreach ($resource in $resourceData) {
        $actionMessage = "querying group for resource: $($resource | ConvertTo-Json)"
 
        # Example: department_<departmentname>
        $groupName = "department_" + $resource.DisplayName

        # Example: title_<titlename>
        # $groupName = "title_" + $resource.Name

        # Sanitize group name, e.g. replace " - " with "_" or other sanitization actions 
        $groupName = Get-SanitizedGroupName -Name $groupName

        $correlationValue = $groupName

        $correlatedResource = $null
        $correlatedResource = $microsoftEntraIDGroupsGrouped["$($correlationValue)"]
        
        #region Calulate action
        if (($correlatedResource | Measure-Object).count -eq 0) {
            $actionResource = "CreateResource"
        }
        elseif (($correlatedResource | Measure-Object).count -eq 1) {
            $actionResource = "CorrelateResource"
        }
        #endregion Calulate action

        #region Process
        switch ($actionResource) {
            "CreateResource" {
                #region Create group
                # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http
                $actionMessage = "creating group for resource: $($resource | ConvertTo-Json)"

                # Example: Microsoft 365 group
                $createGroupBody = @{
                    displayName     = $groupName
                    description     = $groupDescription
                    mailNickname    = $groupName.Replace(" ", "")
                    # visibility      = $groupVisibility # Optional parameter with fixed values. Forexample 'Public' or 'Private'

                    groupTypes      = @("Unified") # Needs to be set to with 'Unified' to create Microsoft 365 group
                    mailEnabled     = $true # Needs to be enabled to create Microsoft 365 group
                    securityEnabled = $false # Needs to be disabled to create Microsoft 365 group

                    # allowExternalSenders = $allowExternalSenders - Not supported with Application permissions
                    # autoSubscribeNewMembers = $autoSubscribeNewMembers - Not supported with Application permissions
                }

                # Example: Microsoft Security group
                # $createGroupBody = @{
                #     displayName     = $groupName
                #     description     = $groupDescription
                #     mailNickname    = $groupName.Replace(" ", "")
                #     # visibility      = $groupVisibility # Optional parameter with fixed values. Forexample 'Public' or 'Private'  

                #     #groupTypes = @("") # Needs to be empty to create Security group
                #     mailEnabled     = $false # Needs to be disabled to create Security group
                #     securityEnabled = $true # Needs to be enabled to create Security group

                #     # allowExternalSenders = $allowExternalSenders - Not supported with Application permissions
                #     # autoSubscribeNewMembers = $autoSubscribeNewMembers - Not supported with Application permissions    
                # }

                $baseUri = "https://graph.microsoft.com/"
                $createGroupSplatParams = @{
                    Uri         = "$($baseUri)/v1.0/groups"
                    Headers     = $headers
                    Method      = "POST"
                    Body        = ($createGroupBody | ConvertTo-Json -Depth 10)
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "SplatParams: $($createGroupSplatParams | ConvertTo-Json)"

                    $createdGroup = Invoke-RestMethod @createGroupSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "CreateResource"
                            Message = "Created group with name [$($groupName)] with id [$($createdGroup.id)]."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would create group with name [$($groupName)] for resource: $($resource | ConvertTo-Json)."
                }
                #endregion Create group

                break
            }

            "CorrelateResource" {
                #region Correlate group
                $actionMessage = "correlating to group for resource: $($resource | ConvertTo-Json)"

                Write-Verbose "Correlated to group with id [$($correlatedResource.id)] on [$($correlationField)] = [$($correlationValue)]."
                #endregion Correlate group

                break
            }
        }
        #endregion Process
    }
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
    
    Write-Warning $warningMessage

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            # Action  = "" # Optional
            Message = $auditMessage
            IsError = $true
        })
}
finally { 
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}
