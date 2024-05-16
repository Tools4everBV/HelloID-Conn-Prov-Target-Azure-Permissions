#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-Groups-List
# List groups as permissions
# Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API: https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0
# PowerShell V2
#################################################
# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($actionContext.Configuration.isDebug) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
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

    #region Microsoft 365 Groups
    #region Get Microsoft Entra ID Microsoft 365 Groups
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Microsoft 365 Groups"

    $microsoftEntraIDM365Groups = [System.Collections.ArrayList]@()
    do {
        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDM365GroupsSplatParams = @{
            Uri         = "$($baseUri)/v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')&`$select=id,displayName,onPremisesSyncEnabled,groupTypes&`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDM365GroupsResult.'@odata.nextLink')) {
            $getMicrosoftEntraIDM365GroupsSplatParams["Uri"] = $getMicrosoftEntraIDM365GroupsResult.'@odata.nextLink'
        }

        $getMicrosoftEntraIDM365GroupsResult = $null
        $getMicrosoftEntraIDM365GroupsResult = Invoke-RestMethod @getMicrosoftEntraIDM365GroupsSplatParams
    
        if ($getMicrosoftEntraIDM365GroupsResult.Value -is [array]) {
            [void]$microsoftEntraIDM365Groups.AddRange($getMicrosoftEntraIDM365GroupsResult.Value)
        }
        else {
            [void]$microsoftEntraIDM365Groups.Add($getMicrosoftEntraIDM365GroupsResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDM365GroupsResult.'@odata.nextLink'))

    Write-Information "Queried Microsoft Entra ID Microsoft 365 Groups. Result count: $(($microsoftEntraIDM365Groups | Measure-Object).Count)"
    #endregion Get Microsoft Entra ID Microsoft 365 Groups

    #region Send results to HelloID
    $microsoftEntraIDM365Groups | ForEach-Object {
        # Shorten DisplayName to max. 100 chars
        $displayName = "M365 Group - $($_.displayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        
        $outputContext.Permissions.Add(
            @{
                displayName    = $displayName
                identification = @{
                    Id   = $_.id
                    Name = $_.displayName
                    Type = "Microsoft 365 Group"
                }
            }
        )
    }
    #endregion Send results to HelloID
    #endregion Microsoft 365 Groups

    #region Security Groups
    #region Get Microsoft Entra ID Security Groups
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Security Groups"

    $microsoftEntraIDSecurityGroups = [System.Collections.ArrayList]@()
    do {
        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDSecurityGroupsSplatParams = @{
            Uri         = "$($baseUri)/v1.0/groups?`$filter=NOT(groupTypes/any(c:c+eq+'DynamicMembership')) and onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true&`$select=id,displayName,onPremisesSyncEnabled,groupTypes&`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDSecurityGroupsResult.'@odata.nextLink')) {
            $getMicrosoftEntraIDSecurityGroupsSplatParams["Uri"] = $getMicrosoftEntraIDSecurityGroupsResult.'@odata.nextLink'
        }

        $getMicrosoftEntraIDSecurityGroupsResult = $null
        $getMicrosoftEntraIDSecurityGroupsResult = Invoke-RestMethod @getMicrosoftEntraIDSecurityGroupsSplatParams
    
        if ($getMicrosoftEntraIDSecurityGroupsResult.Value -is [array]) {
            [void]$microsoftEntraIDSecurityGroups.AddRange($getMicrosoftEntraIDSecurityGroupsResult.Value)
        }
        else {
            [void]$microsoftEntraIDSecurityGroups.Add($getMicrosoftEntraIDSecurityGroupsResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDSecurityGroupsResult.'@odata.nextLink'))

    Write-Information "Queried Microsoft Entra ID Security Groups. Result count: $(($microsoftEntraIDSecurityGroups | Measure-Object).Count)"
    #endregion Get Microsoft Entra ID account

    #region Send results to HelloID
    $microsoftEntraIDSecurityGroups | ForEach-Object {
        # Shorten DisplayName to max. 100 chars
        $displayName = "Security Group - $($_.displayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        
        $outputContext.Permissions.Add(
            @{
                displayName    = $displayName
                identification = @{
                    Id   = $_.id
                    Name = $_.displayName
                    Type = "Security Group"
                }
            }
        )
    }
    #endregion Send results to HelloID
    #endregion Security Groups
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    # Set Success to false
    $outputContext.Success = $false

    # Required to write an error as the listing of permissions doesn't show auditlog
    Write-Error $auditMessage
}