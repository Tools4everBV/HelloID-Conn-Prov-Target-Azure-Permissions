#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Create
# Create and update or correlate to account
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
$correlationField = $actionContext.CorrelationConfiguration.accountField
$correlationValue = $actionContext.CorrelationConfiguration.accountFieldValue

# Define account object
$account = [PSCustomObject]$actionContext.Data
# Remove properties phoneAuthenticationMethod, emailAuthenticationMethod and manager as they are set within seperate actions
$account = $account | Select-Object -ExcludeProperty phoneAuthenticationMethod, emailAuthenticationMethod, manager

# Define properties to query
$accountPropertiesToQuery = @("id") + $account.PsObject.Properties.Name | Select-Object -Unique

# Remove properties of account object with null-values
$account.PsObject.Properties | ForEach-Object {
    # Remove properties with null-values
    if ($_.Value -eq $null) {
        $account.PsObject.Properties.Remove("$($_.Name)")
    }
}
# Convert the properties of account object containing "TRUE" or "FALSE" to boolean 
$account = Convert-StringToBoolean $account
#endRegion account

#region manager account
if ($actionContext.Configuration.setPrimaryManagerOnCreate -eq $true) {
    # Define correlation
    $managerCorrelationField = "employeeId"
    $managerCorrelationValue = $personContext.Manager.ExternalId

    # Define properties to query
    $managerAccountPropertiesToQuery = @("id")
}
#endRegion manager account

#region guestInvite
if ($actionContext.Configuration.inviteAsGuest -eq $true) {
    # Define correlation
    $guestInviteAccount = [PSCustomObject]$actionContext.Data.guestInvite
    # Remove properties with null-values
    $guestInviteAccount.PsObject.Properties | ForEach-Object {
        # Remove properties with null-values
        if ($_.Value -eq $null) {
            $guestInviteAccount.PsObject.Properties.Remove("$($_.Name)")
        }
    }
    # Convert the properties containing "TRUE" or "FALSE" to boolean
    $guestInviteAccount = Convert-StringToBoolean $guestInviteAccount
}
#endRegion guestInvite

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

    #region Verify correlation configuration and properties
    $actionMessage = "verifying correlation configuration and properties"


    if ($actionContext.CorrelationConfiguration.Enabled -eq $true) {
        if ([string]::IsNullOrEmpty($correlationField)) {
            throw "Correlation is enabled but not configured correctly."
        }
    
        if ([string]::IsNullOrEmpty($correlationValue)) {
            throw "The correlation value for [$correlationField] is empty. This is likely a mapping issue."
        }

        #region Get Microsoft Entra ID account
        # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying Microsoft Entra ID account"

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
    }
    else {
        if ($actionContext.Configuration.correlateOnly -eq $true) {
            throw "Correlation is disabled while configuration option [correlateOnly] is toggled."
        }
        else {
            Write-Warning "Correlation is disabled."
        }
    }
    #endregion Verify correlation configuration and properties

    #region Account
    #region Calulate action
    $actionMessage = "calculating action"
    if (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 0) {
        if ($actionContext.Configuration.correlateOnly -eq $true) {
            $actionAccount = "NotFound"
        }
        else {
            $actionAccount = "Create"
            if ($actionContext.Configuration.inviteAsGuest -eq $true) {
                $actionAccountCreate = "GuestInvite"
            }
            else {
                $actionAccountCreate = "Create"
            }
        }
    }
    elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 1) {
        $actionAccount = "Correlate"
    }
    elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -gt 1) {
        $actionAccount = "MultipleFound"
    }
    #endregion Calulate action
    
    #region Process
    switch ($actionAccount) {
        "Create" {
            switch ($actionAccountCreate) {
                "Create" {
                    #region Create account                  
                    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0&tabs=http
                    $actionMessage = "creating account"
                    $baseUri = "https://graph.microsoft.com/"

                    # Create account with only required fields
                    $requiredFields = @("accountEnabled", "displayName", "mailNickname", "passwordProfile", "userPrincipalName")
                    $createAccountBody = @{}
                    foreach ($accountProperty in $account.PsObject.Properties | Where-Object { $null -ne $_.Value -and $_.Name -in $requiredFields }) {
                        [void]$createAccountBody.Add($accountProperty.Name, $accountProperty.Value)
                    }

                    $createAccountSplatParams = @{
                        Uri         = "$($baseUri)/v1.0/users"
                        Headers     = $headers
                        Method      = "POST"
                        Body        = ($createAccountBody | ConvertTo-Json -Depth 10)
                        Verbose     = $false
                        ErrorAction = "Stop"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "SplatParams: $($createAccountSplatParams | ConvertTo-Json)"

                        $createdAccount = Invoke-RestMethod @createAccountSplatParams

                        #region Set AccountReference and add AccountReference to Data
                        $outputContext.AccountReference = "$($createdAccount.id)"
                        $outputContext.Data.id = "$($createdAccount.id)"
                        #endregion Set AccountReference and add AccountReference to Data

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Created account with displayName [$($createAccountBody.displayName)] and userPrincipalName [$($createAccountBody.userPrincipalName)] with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Would create account with displayName [$($createAccountBody.displayName)] and userPrincipalName [$($createAccountBody.userPrincipalName)]."
                    }
                    #endregion Create account
                        
                    break
                }

                "GuestInvite" {
                    #region Create invitation
                    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/invitation-post?view=graph-rest-1.0&tabs=http
                    $actionMessage = "creating invitation"
                    $baseUri = "https://graph.microsoft.com/"

                    $createInvitationBody = $guestInviteAccount

                    $createInvitationSplatParams = @{
                        Uri         = "$($baseUri)/v1.0/invitations"
                        Headers     = $headers
                        Method      = "POST"
                        Body        = ($createInvitationBody | ConvertTo-Json -Depth 10)
                        Verbose     = $false
                        ErrorAction = "Stop"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "SplatParams: $($createInvitationSplatParams | ConvertTo-Json)"

                        $createdInvitation = Invoke-RestMethod @createInvitationSplatParams

                        #region Set AccountReference and add AccountReference to Data
                        $outputContext.AccountReference = "$($createdInvitation.invitedUser.id)"
                        $outputContext.Data.id = "$($createdInvitation.invitedUser.id)"
                        #endregion Set AccountReference and add AccountReference to Data

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Created invitiation for user with displayName [$($createInvitationBody.invitedUserDisplayName)] and emailAddress [$($createInvitationBody.invitedUserEmailAddress)] with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Would create invitiation for user with displayName [$($createInvitationBody.invitedUserDisplayName)] and emailAddress [$($createInvitationBody.invitedUserEmailAddress)]."
                    }
                    #endregion Create invitation

                    break
                }
            }

            #region Update account
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http
            $actionMessage = "updating created account"
            $baseUri = "https://graph.microsoft.com/"

            # Update account with all other fields than the required fields
            $updateAccountBody = @{}
            foreach ($accountProperty in $account.PsObject.Properties | Where-Object { $null -ne $_.Value -and $_.Name -notin $requiredFields }) {
                [void]$updateAccountBody.Add($accountProperty.Name, $accountProperty.Value)
            }

            $updateAccountSplatParams = @{
                Uri         = "$($baseUri)/v1.0/users/$($outputContext.AccountReference)"
                Headers     = $headers
                Method      = "PATCH"
                Body        = ($updateAccountBody | ConvertTo-Json -Depth 10)
                Verbose     = $false
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                Write-Verbose "SplatParams: $($updateAccountSplatParams | ConvertTo-Json)"

                $updatedAccount = Invoke-RestMethod @updateAccountSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Updated created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would update created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
            }
            #endregion Update account

            #region Manager
            if ($actionContext.Configuration.setPrimaryManagerOnCreate -eq $true) {
                #region Use Manager Reference
                if (-not[String]::IsNullOrEmpty(($actionContext.References.ManagerAccount))) {
                    $currentMicrosoftEntraIDManagerAccountId = $actionContext.References.ManagerAccount
                }
                #endregion Use Manager Reference
                #region If Manager Reference is not available, correlate to manager
                else {
                    #region Verify manager correlation configuration and properties
                    $actionMessage = "verifying manager correlation configuration and properties"
                    if (-not[string]::IsNullOrEmpty($managerCorrelationValue)) {
                        #region Get manager Microsoft Entra ID account
                        # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
                        $actionMessage = "querying manager Microsoft Entra ID account"

                        $baseUri = "https://graph.microsoft.com/"
                        $getMicrosoftEntraIDManagerAccountSplatParams = @{
                            Uri         = "$($baseUri)/v1.0/users?`$filter=$managerCorrelationField eq '$managerCorrelationValue'&`$select=$($managerAccountPropertiesToQuery -join ',')"
                            Headers     = $headers
                            Method      = "GET"
                            Verbose     = $false
                            ErrorAction = "Stop"
                        }
                        $currentMicrosoftEntraIDManagerAccount = $null
                        $currentMicrosoftEntraIDManagerAccount = (Invoke-RestMethod @getMicrosoftEntraIDManagerAccountSplatParams).Value

                        $currentMicrosoftEntraIDManagerAccountId = $currentMicrosoftEntraIDManagerAccount.Id

                        Write-Verbose "Queried manager Microsoft Entra ID account where [$($managerCorrelationField)] = [$($managerCorrelationValue)]. Result: $($currentMicrosoftEntraIDManagerAccount | ConvertTo-Json)"
                        #endregion Get manager Microsoft Entra ID account
                    }
                    #endregion Verify correlation configuration and properties
                }
                #endregion If Manager Reference is not available, correlate to manager

                #region Calulate manager action
                $actionMessage = "calculating manager action"

                if (($currentMicrosoftEntraIDManagerAccountId | Measure-Object).count -eq 1) {
                    $actionMessage = "comparing current manager to mapped manager"
    
                    if ($currentMicrosoftEntraIDManagerAccountId -ne $previousMicrosoftEntraIDManagerAccountId) {
                        $actionManager = "Update"
                    }
                    else {
                        $actionManager = "NoChanges"
                    }            
    
                    Write-Verbose "Compared current manager to mapped manager. Result: $actionManager"
                }
                elseif (($currentMicrosoftEntraIDManagerAccountId | Measure-Object).count -gt 1) {
                    $actionManager = "MultipleFound"
                }
                elseif (($currentMicrosoftEntraIDManagerAccountId | Measure-Object).count -eq 0) {
                    if ([string]::IsNullOrEmpty($managerCorrelationValue)) {
                        $actionManager = "CorrelationValueEmpty"
                    }
                    else {
                        $actionManager = "NotFound"  
                    }
                }
                #endregion Calulate manager action
                
                #region Calulate manager action
                $actionMessage = "calculating manager action"

                if (($currentMicrosoftEntraIDManagerAccountId | Measure-Object).count -eq 1) {
                    $actionManager = "Set"
                }
                elseif (($currentMicrosoftEntraIDManagerAccountId | Measure-Object).count -gt 1) {
                    $actionManager = "MultipleFound"
                }
                elseif (($currentMicrosoftEntraIDManagerAccountId | Measure-Object).count -eq 0) {
                    if ([string]::IsNullOrEmpty($managerCorrelationValue)) {
                        $actionManager = "CorrelationValueEmpty"
                    }
                    else {
                        $actionManager = "NotFound"
                    }
                }
                #endregion Calulate manager action

                switch ($actionManager) {
                    "Set" {
                        #region Set Manager
                        # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-post-manager?view=graph-rest-1.0&tabs=http
                        $actionMessage = "setting manager for created account"
                        $baseUri = "https://graph.microsoft.com/"

                        # Update account with all other fields than the required fields
                        $setManagerBody = @{
                            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($currentMicrosoftEntraIDManagerAccountId)"
                        }

                        $setManagerSplatParams = @{
                            Uri         = "$($baseUri)/v1.0/users/$($outputContext.AccountReference)/manager/`$ref"
                            Headers     = $headers
                            Method      = "PUT"
                            Body        = ($setManagerBody | ConvertTo-Json -Depth 10)
                            Verbose     = $false
                            ErrorAction = "Stop"
                        }

                        if (-Not($actionContext.DryRun -eq $true)) {
                            Write-Verbose "SplatParams: $($setManagerSplatParams | ConvertTo-Json)"

                            $setManager = Invoke-RestMethod @setManagerSplatParams

                            #region Add Manager AccountReference to Data
                            $outputContext.Data.manager.id = "$($currentMicrosoftEntraIDManagerAccountId)"
                            #endregion Add Manager AccountReference to Data

                            $outputContext.AuditLogs.Add([PSCustomObject]@{
                                    # Action  = "" # Optional
                                    Message = "Set manager for created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). New value: $($currentMicrosoftEntraIDManagerAccountId | ConvertTo-Json)"
                                    IsError = $false
                                })
                        }
                        else {
                            Write-Warning "DryRun: Would set manager for created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). New value: $($currentMicrosoftEntraIDManagerAccountId | ConvertTo-Json)"
                        }
                        #endregion Set Manager

                        break
                    }

                    "MultipleFound" {
                        #region Multiple accounts found
                        $actionMessage = "setting manager for created account"
        
                        # Throw terminal error
                        throw "Multiple accounts found where [$($managerCorrelationField)] = [$($managerCorrelationValue)]. Please correct this so the persons are unique."
                        #endregion Multiple accounts found
        
                        break
                    }
        
                    "NotFound" {
                        #region No account found
                        $actionMessage = "setting manager for created account"

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Skipped setting manager for created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Reason: No account found where [$($managerCorrelationField)] = [$($managerCorrelationValue)]."
                                IsError = $false
                            })
                        #endregion No account found
        
                        break
                    }

                    "CorrelationValueEmpty" {
                        #region No account found
                        $actionMessage = "setting manager for created account"

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Skipped setting manager for created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Reason: Manager correlation value for [$managerCorrelationField] is empty."
                                IsError = $false
                            })
                        #endregion No account found
        
                        break
                    }
                }
            }
            #endregion Manager

            break
        }

        "Correlate" {
            #region Correlate account
            $actionMessage = "correlating to account"

            $outputContext.AccountReference = "$($currentMicrosoftEntraIDAccount.id)"
            $outputContext.Data = $currentMicrosoftEntraIDAccount

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                    Message = "Correlated to account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json) on [$($correlationField)] = [$($correlationValue)]."
                    IsError = $false
                })

            $outputContext.AccountCorrelated = $true
            #endregion Correlate account

            break
        }

        "MultipleFound" {
            #region Multiple accounts found
            $actionMessage = "correlating to account"

            # Throw terminal error
            throw "Multiple accounts found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the persons are unique."
            #endregion Multiple accounts found

            break
        }

        "NotFound" {
            #region No account found
            $actionMessage = "correlating to account"
        
            # Throw terminal error
            throw "No account found where [$($correlationField)] = [$($correlationValue)] while configuration option [correlateOnly] is toggled."
            #endregion No account found

            break
        }
    }
    #endregion Process
    #endregion Account
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

    # Check if accountreference is set, if not set, set this with default value as this must contain a value
    if ([String]::IsNullOrEmpty($outputContext.AccountReference) -and $actionContext.DryRun -eq $true) {
        $outputContext.AccountReference = "DryRun: Currently not available"
    }
}