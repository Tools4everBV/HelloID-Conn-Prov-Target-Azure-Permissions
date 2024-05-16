#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-EmailAuthenticationMethod-Revoke
# Revoke email authentication method of account
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

    #region emailAuthenticationMethod
    #region Get current emailAuthenticationMethod
    # Microsoft docs: https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-get?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying email authentication methods for account"

    $baseUri = "https://graph.microsoft.com/"
    $getCurrentEmailAuthenticationMethodsSplatParams = @{
        Uri         = "$($baseUri)/v1.0/users/$($actionContext.References.Account)/authentication/emailMethods"
        Headers     = $headers
        Method      = "GET"
        Verbose     = $false
        ErrorAction = "Stop"
    }

    $currentEmailAuthenticationMethods = $null
    $currentEmailAuthenticationMethods = (Invoke-RestMethod @getCurrentEmailAuthenticationMethodsSplatParams).Value

    $currentEmailAuthenticationMethod = ($currentEmailAuthenticationMethods | Where-Object { $_.id -eq "$($actionContext.References.Permission.Id)" }).emailAddress

    Write-Verbose "Queried email authentication methods for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Result: $($currentEmailAuthenticationMethods | ConvertTo-Json)"
    #endregion Get current emailAuthenticationMethod

    #region Calulate action
    $actionMessage = "calculating action"
    if (($currentEmailAuthenticationMethod | Measure-Object).count -eq 1) {
        if ($actionContext.Configuration."$($actionContext.References.Permission.RemoveWhenRevokingEntitlement)" -eq $false) {
            $actionEmailAuthenticationMethod = "SkipDelete"
        }
        else {
            $actionEmailAuthenticationMethod = "Delete"
        }
    }
    elseif (($currentEmailAuthenticationMethod | Measure-Object).count -eq 0) {
        $actionEmailAuthenticationMethod = "NoExistingData-SkipDelete"
    }
    #endregion Calulate action

    #region Process
    switch ($actionEmailAuthenticationMethod) {
        "Delete" {
            #region Delete emailAuthenticationMethod
            # Microsoft docs: https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-delete?view=graph-rest-1.0&tabs=http
            $actionMessage = "deleting email authentication method [$($actionContext.References.Permission.Name)] for account"
            $baseUri = "https://graph.microsoft.com/"
                    
            $deleteEmailAuthenticationMethodSplatParams = @{
                Uri         = "$baseUri/v1.0/users/$($actionContext.References.Account)/authentication/emailMethods/$($actionContext.References.Permission.Id)"
                Headers     = $headers
                Method      = "DELETE"
                Verbose     = $false
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                Write-Verbose "SplatParams: $($deleteEmailAuthenticationMethodSplatParams | ConvertTo-Json)"

                $deletedEmailAuthenticationMethod = Invoke-RestMethod @deleteEmailAuthenticationMethodSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Deleted email authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old value: [$($currentEmailAuthenticationMethod)]."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would delete email authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old value: [$($currentEmailAuthenticationMethod)]."
            }
            #endregion Delete emailAuthenticationMethod

            break
        }

        "SkipDelete" {
            #region Skip delete
            $actionMessage = "skipping deleting email authentication method [$($actionContext.References.Permission.Name)] for account"

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped deleting email authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old value: [$($currentEmailAuthenticationMethod)]. Reason: Configured to not delete on revoke of entitlement."
                    IsError = $false
                })
            #endregion Skip delete
    
            break
        }

        "NoExistingData-SkipDelete" {
            #region No existing data, skipping delete
            $actionMessage = "skipping deleting email authentication method [$($actionContext.References.Permission.Name)] for account"
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped deleting email authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old value: [$($currentEmailAuthenticationMethod)]. Reason: Nothing to delete."
                    IsError = $false
                })
            #endregion  No existing data, skipping delete

            break
        }
    }
    #endregion Process
    #endregion emailAuthenticationMethod
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
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
    if ($outputContext.AuditLogs.IsError -contains $true) {
        $outputContext.Success = $false
    }
    else {
        $outputContext.Success = $true
    }
}