#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-PhoneAuthenticationMethod-Grant
# Grant phone authentication method of account
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

#region phoneAuthenticationMethod
# Define phonenumber
switch ($actionContext.References.Permission.Name) {
    "mobile" {
        $phoneNumber = $personContext.Person.Contact.Business.Phone.Mobile

        break
    }

    "alternateMobile" {
        $phoneNumber = $personContext.Person.Contact.Business.Phone.Fixed

        break
    }

    "office" {
        $phoneNumber = $personContext.Person.Contact.Personal.Phone.Mobile

        break
    }
}

# Formate phoneNumber to supported format
if ($null -ne $phoneNumber -and $phoneNumber) {
    # Remove spaces and -
    $phoneNumber = $phoneNumber -replace "-", "" -replace "\s", ""

    # Replace 06 with +316
    if ($phoneNumber.StartsWith("06")) {
        $phoneNumber = "+316" + $phoneNumber.Substring(2)
        # Replace 0031 with +31
    }
    elseif ($phoneNumber.StartsWith("0031")) {
        $phoneNumber = "+31" + $phoneNumber.Substring(4)
        # Replace 00 with +
    }
    elseif ($phoneNumber.StartsWith("00")) {
        $phoneNumber = "+" + $phoneNumber.Substring(2)
    }

    # Make sure it starts with +
    if (-not $phoneNumber.StartsWith("+")) {
        $phoneNumber = "+" + $phoneNumber
    }
}
#endRegion phoneAuthenticationMethod

try {
    #region Verify account reference and required properties
    $actionMessage = "verifying account reference and required properties"
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }

    if ( [string]::IsNullOrEmpty($phoneNumber) ) {
        throw "The value for [$($actionContext.References.Permission.Name)] is empty. This is likely a mapping issue."
    }
    #endregion Verify account reference and required properties

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

    #region phoneAuthenticationMethod
    if ($null -ne $actionContext.References.Account) {
        #region Get current phoneAuthenticationMethod
        # Microsoft docs: https://learn.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-get?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying phone authentication methods"

        $baseUri = "https://graph.microsoft.com/"
        $getCurrentPhoneAuthenticationMethodsSplatParams = @{
            Uri         = "$($baseUri)/v1.0/users/$($actionContext.References.Account)/authentication/phoneMethods"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }

        $currentPhoneAuthenticationMethods = $null
        $currentPhoneAuthenticationMethods = (Invoke-RestMethod @getCurrentPhoneAuthenticationMethodsSplatParams).Value

        $currentPhoneAuthenticationMethod = ($currentPhoneAuthenticationMethods | Where-Object { $_.phoneType -eq "$($actionContext.References.Permission.Name)" }).phoneNumber

        Write-Verbose "Queried phone authentication methods for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Result: $($currentPhoneAuthenticationMethods | ConvertTo-Json)"
        #endregion Get current phoneAuthenticationMethod

        #region Calulate action
        $actionMessage = "calculating action"
        if (($currentPhoneAuthenticationMethod | Measure-Object).count -eq 0) {
            $actionPhoneAuthenticationMethod = "Create"
        }
        elseif (($currentPhoneAuthenticationMethod | Measure-Object).count -eq 1) {
            # Remove spaces (Microsoft Entra ID formats and returns the phonenumber with a space after the country code)
            $currentPhoneAuthenticationMethod = $currentPhoneAuthenticationMethod.replace(" ", "")
            if ($currentPhoneAuthenticationMethod -ne $($phoneNumber)) {
                if ($actionContext.References.Permission.OnlySetWhenEmpty -eq $true) {
                    $actionPhoneAuthenticationMethod = "ExistingData-SkipUpdate"
                }
                else {
                    $actionPhoneAuthenticationMethod = "Update"
                }
            }
            else {
                $actionPhoneAuthenticationMethod = "NoChanges"
            }
        }
        #endregion Calulate action

        #region Process
        switch ($actionPhoneAuthenticationMethod) {
            "Create" {
                #region Create phoneAuthenticationMethod
                # Microsoft docs: https://learn.microsoft.com/nl-nl/graph/api/authentication-post-phonemethods?view=graph-rest-1.0&tabs=http
                $actionMessage = "creating phone authentication method [$($actionContext.References.Permission.Name)] for account"
                $baseUri = "https://graph.microsoft.com/"

                $createPhoneAuthenticationMethodBody = @{
                    "phoneNumber" = $($phoneNumber)
                    "phoneType"   = $($actionContext.References.Permission.Name)
                }

                $createPhoneAuthenticationMethodSplatParams = @{
                    Uri         = "$($baseUri)/v1.0/users/$($actionContext.References.Account)/authentication/phoneMethods"
                    Headers     = $headers
                    Method      = "POST"
                    Body        = ($createPhoneAuthenticationMethodBody | ConvertTo-Json -Depth 10)
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "No current phone authentication method set for [$($actionContext.References.Permission.Name)]. SplatParams: $($createPhoneAuthenticationMethodSplatParams | ConvertTo-Json)"

                    $createdPhoneAuthenticationMethod = Invoke-RestMethod @createPhoneAuthenticationMethodSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created phone authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). New value: [$($phoneNumber)]."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would create phone authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). New value: [$($phoneNumber)]."
                }
                #endregion Create phoneAuthenticationMethod

                break
            }

            "Update" {
                #region Update phoneAuthenticationMethod
                # Microsoft docs: https://learn.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-update?view=graph-rest-1.0&tabs=http
                $actionMessage = "updating phone authentication method [$($actionContext.References.Permission.Name)] for account"
                $baseUri = "https://graph.microsoft.com/"

                $updatePhoneAuthenticationMethodBody = @{
                    "phoneNumber" = $($phoneNumber)
                    "phoneType"   = $($actionContext.References.Permission.Name)
                }

                $updatePhoneAuthenticationMethodSplatParams = @{
                    Uri         = "$($baseUri)/v1.0/users/$($actionContext.References.Account)/authentication/phoneMethods/$($actionContext.References.Permission.Id)"
                    Headers     = $headers
                    Method      = "PATCH"
                    Body        = ($updatePhoneAuthenticationMethodBody | ConvertTo-Json -Depth 10)
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "SplatParams: $($updatePhoneAuthenticationMethodSplatParams | ConvertTo-Json)"

                    $updatedPhoneAuthenticationMethod = Invoke-RestMethod @updatePhoneAuthenticationMethodSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Updated phone authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old value: [$($currentPhoneAuthenticationMethod)]. New value: [$($phoneNumber)]."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would update phone authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old value: [$($currentPhoneAuthenticationMethod)]. New value: [$($phoneNumber)]."
                }
                #endregion Update phoneAuthenticationMethod

                break
            }

            "NoChanges" {
                #region No changes
                $actionMessage = "skipping setting phone authentication method [$($actionContext.References.Permission.Name)] for account"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Skipped setting phone authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old value: [$($currentPhoneAuthenticationMethod)]. New value: [$($phoneNumber)]. Reason: No changes."
                        IsError = $false
                    })
                #endregion No changes

                break
            }

            "ExistingData-SkipUpdate" {
                #region Existing data, skipping update
                $actionMessage = "skipping setting phone authentication method [$($actionContext.References.Permission.Name)] for account"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Skipped setting phone authentication method [$($actionContext.References.Permission.Name)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old value: [$($currentPhoneAuthenticationMethod)]. New value: [$($phoneNumber)]. Reason: Configured to only update when empty and already contains data."
                        IsError = $false
                    })
                #endregion Existing data, skipping update

                break
            }
        }
        #endregion Process
    }
    #endregion phoneAuthenticationMethod
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