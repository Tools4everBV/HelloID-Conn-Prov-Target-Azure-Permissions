#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-UniquenessCheck
# Check if fields are unique
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

#region Fields to check
$fieldsToCheck = [PSCustomObject]@{
    "userPrincipalName" = [PSCustomObject]@{
        accountValue   = $actionContext.Data.userPrincipalName
        keepInSyncWith = @("mail", "mailNickname") # The properties to keep in sync with, if one of these properties isn't unique, this property wil be treated as not unique as well
        crossCheckOn   = @("userPrincipalName", "mailNickname") # The properties to keep in cross-check on
    }
    "mail"              = [PSCustomObject]@{ # This is the value that is returned to HelloID in NonUniqueFields
        accountValue   = $actionContext.Data.mail
        keepInSyncWith = @("userPrincipalName", "mailNickname") # The properties to keep in sync with, if one of these properties isn't unique, this property wil be treated as not unique as well
        crossCheckOn   = @("userPrincipalName", "mailNickname") # The properties to keep in cross-check on
    }
    "mailNickname"      = [PSCustomObject]@{ # This is the value that is returned to HelloID in NonUniqueFields
        accountValue   = $actionContext.Data.mailNickname
        keepInSyncWith = @("userPrincipalName", "mail") # The properties to keep in sync with, if one of these properties isn't unique, this property wil be treated as not unique as well
        crossCheckOn   = $null # The properties to keep in cross-check on
    }
}
#endregion Fields to check

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

    if ($actionContext.Operation.ToLower() -ne "create") {
        #region Verify account reference
        $actionMessage = "verifying account reference"
        if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
            throw "The account reference could not be found"
        }
        #endregion Verify account reference
    }
    foreach ($fieldToCheck in $fieldsToCheck.PsObject.Properties | Where-Object { -not[String]::IsNullOrEmpty($_.Value.accountValue) }) {
        #region Get Microsoft Entra ID account
        # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying Microsoft Entra ID account where [$($fieldToCheck.Name)] = [$($fieldToCheck.Value.accountValue)]"

        $baseUri = "https://graph.microsoft.com/"
        $filter = "$($fieldToCheck.Name) eq '$($fieldToCheck.Value.accountValue)'"
        if (($fieldToCheck.Value.crossCheckOn | Measure-Object).Count -ge 1) {
            foreach ($fieldToCrossCheckOn in $fieldToCheck.Value.crossCheckOn) {
                $filter = $filter + " OR $($fieldToCrossCheckOn) eq '$($fieldToCheck.Value.accountValue)'"
            }
        }
        $getMicrosoftEntraIDAccountSplatParams = @{
            Uri         = "$($baseUri)/v1.0/users?`$filter=$($filter)&`$select=id,$($fieldToCheck.Name)"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        $currentMicrosoftEntraIDAccount = $null
        $currentMicrosoftEntraIDAccount = (Invoke-RestMethod @getMicrosoftEntraIDAccountSplatParams).Value

        Write-Verbose "Queried Microsoft Entra ID account where [$($fieldToCheck.Name)] = [$($fieldToCheck.Value.accountValue)]. Result: $($currentMicrosoftEntraIDAccount | ConvertTo-Json)."
        #endregion Get Microsoft Entra ID account

        #region Check property uniqueness
        $actionMessage = "checking if property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique in Microsoft Entra ID"
        if (($currentMicrosoftEntraIDAccount | Measure-Object).count -gt 0) {
            if ($actionContext.Operation.ToLower() -ne "create" -and $currentMicrosoftEntraIDAccount.id -eq $actionContext.References.Account) {
                Write-Verbose "Person is using property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] themselves."
            }
            else {
                Write-Verbose "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is not unique in Microsoft Entra ID."
                Write-Verbose "In use by: $($currentMicrosoftEntraIDAccount | ConvertTo-Json)."
                [void]$outputContext.NonUniqueFields.Add($fieldToCheck.Name)
                
                if (($fieldToCheck.Value.keepInSyncWith | Measure-Object).Count -ge 1) {
                    foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $actionContext.Data.PsObject.Properties }) {
                        [void]$outputContext.NonUniqueFields.Add($fieldToKeepInSyncWith)
                    }
                }
            }
        }
        elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 0) {
            Write-Verbose "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique in Microsoft Entra ID."
        }
        #endregion Check property uniqueness
    }

    # Set Success to true
    $outputContext.Success = $true
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

    # Required to write an error as uniqueness check doesn't show auditlog
    Write-Error $auditMessage
}