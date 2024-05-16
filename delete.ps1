#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Delete
# Delete account
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

#region account
# Define correlation
$correlationField = "id"
$correlationValue = $actionContext.References.Account
#endRegion account

try {
    if ($actionContext.Configuration.correlateOnly -eq $true) {
        #region Correlate only
        $actionMessage = "skipping deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Skipped deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: Configuration option [correlateOnly] is toggled."
                IsError = $false
            })
        #region Correlate only
    }
    else {
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

        #region Get Microsoft Entra ID account
        # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying Microsoft Entra ID account where [$($correlationField)] = [$($correlationValue)]"

        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDAccountSplatParams = @{
            Uri         = "$($baseUri)/v1.0/users?`$filter=$correlationField eq '$correlationValue'&`$select=$($accountPropertiesToQuery -join ',')"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        $currentMicrosoftEntraIDAccount = $null
        $currentMicrosoftEntraIDAccount = (Invoke-RestMethod @getMicrosoftEntraIDAccountSplatParams).Value

        Write-Verbose "Queried Microsoft Entra ID account where [$($correlationField)] = [$($correlationValue)]. Result: $($currentMicrosoftEntraIDAccount | ConvertTo-Json)"
        #endregion Get Microsoft Entra ID account

        #region Account
        #region Calulate action
        $actionMessage = "calculating action"
        if (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 1) {
            $actionAccount = "Delete"
        }
        elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -gt 1) {
            $actionAccount = "MultipleFound"
        }
        elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 0) {
            $actionAccount = "NotFound"
        }
        #endregion Calulate action

        #region Process
        switch ($actionAccount) {
            "Delete" {
                #region Delete account
                # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-delete?view=graph-rest-1.0&tabs=http
                $actionMessage = "deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"
                $baseUri = "https://graph.microsoft.com/"

                $deleteAccountSplatParams = @{
                    Uri         = "$($baseUri)/v1.0/users/$($actionContext.References.Account)"
                    Headers     = $headers
                    Method      = "DELETE"
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). SplatParams: $($deleteAccountSplatParams | ConvertTo-Json)"

                    $deletedAccount = Invoke-RestMethod @deleteAccountSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Deleted account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would delete account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                }
                #endregion Delete account

                break
            }

            "MultipleFound" {
                #region Multiple accounts found
                $actionMessage = "deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

                # Throw terminal error
                throw "Multiple accounts found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the persons are unique."
                #endregion Multiple accounts found

                break
            }

            "NotFound" {
                #region No account found
                $actionMessage = "skipping deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Skipped deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No account found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
                        IsError = $true
                    })
                #endregion No account found

                break
            }
        }
        #endregion Process
        #endregion Account
    }
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

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            # Action  = "" # Optional
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if ($outputContext.AuditLogs.IsError -contains $true) {
        $outputContext.Success = $false
    }
    else {
        $outputContext.Success = $true
    }
}