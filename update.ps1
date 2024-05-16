#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Update
# Update account
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

# Define properties to compare for update
$accountPropertiesToCompare = $account.PsObject.Properties.Name
#endRegion account

#region manager account
# Define correlation
$managerCorrelationField = "employeeId"
$managerCorrelationValue = $personContext.Manager.ExternalId

# Define properties to query
$managerAccountPropertiesToQuery = @("id")
#endRegion manager account

try {
    if ($actionContext.Configuration.correlateOnly -eq $true) {
        #region Correlate only
        $actionMessage = "skipping updating account"
        
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Skipped updating account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: Configuration option [correlateOnly] is toggled."
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

        #region Account
        #region Calulate action
        $actionMessage = "calculating action"
        if (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 1) {
            $actionMessage = "comparing current account to mapped properties"

            # Set Previous data (if there are no changes between PreviousData and Data, HelloID will log "update finished with no changes")
            $outputContext.PreviousData = $currentMicrosoftEntraIDAccount

            # Create reference object from correlated account
            $accountReferenceObject = [PSCustomObject]@{}
            foreach ($currentMicrosoftEntraIDAccountProperty in ($currentMicrosoftEntraIDAccount | Get-Member -MemberType NoteProperty)) {
                # Add property using -join to support array values
                $accountReferenceObject | Add-Member -MemberType NoteProperty -Name $currentMicrosoftEntraIDAccountProperty.Name -Value ($currentMicrosoftEntraIDAccount.$($currentMicrosoftEntraIDAccountProperty.Name) -join ",") -Force
            }

            # Create difference object from mapped properties
            $accountDifferenceObject = [PSCustomObject]@{}
            foreach ($accountAccountProperty in $account.PSObject.Properties) {
                # Add property using -join to support array values
                $accountDifferenceObject | Add-Member -MemberType NoteProperty -Name $accountAccountProperty.Name -Value ($accountAccountProperty.Value -join ",") -Force
            }

            $accountSplatCompareProperties = @{
                ReferenceObject  = $accountReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $accountPropertiesToCompare }
                DifferenceObject = $accountDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $accountPropertiesToCompare }
            }
            if ($null -ne $accountSplatCompareProperties.ReferenceObject -and $null -ne $accountSplatCompareProperties.DifferenceObject) {
                $accountPropertiesChanged = Compare-Object @accountSplatCompareProperties -PassThru
                $accountOldProperties = $accountPropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
                $accountNewProperties = $accountPropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
            }

            if ($accountNewProperties) {
                $actionAccount = "Update"
                Write-Information "Account property(s) required to update: $($accountNewProperties.Name -join ', ')"
            }
            else {
                $actionAccount = "NoChanges"
            }            

            Write-Verbose "Compared current account to mapped properties. Result: $actionAccount"
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
            "Update" {
                #region Update account
                # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http
                $actionMessage = "updating account"
                # Create custom object with old and new values (for logging)
                $accountChangedPropertiesObject = [PSCustomObject]@{
                    OldValues = @{}
                    NewValues = @{}
                }

                foreach ($accountOldProperty in ($accountOldProperties | Where-Object { $_.Name -in $accountNewProperties.Name })) {
                    $accountChangedPropertiesObject.OldValues.$($accountOldProperty.Name) = $accountOldProperty.Value
                }

                foreach ($accountNewProperty in $accountNewProperties) {
                    $accountChangedPropertiesObject.NewValues.$($accountNewProperty.Name) = $accountNewProperty.Value
                }

                $baseUri = "https://graph.microsoft.com/"

                # Set output data with current account data
                $outputContext.Data = $currentMicrosoftEntraIDAccount

                # Update account with updated fields
                $updateAccountBody = @{}
                foreach ($accountNewProperty in $accountNewProperties) {
                    [void]$updateAccountBody.Add($accountNewProperty.Name, $accountNewProperty.Value)

                    # Update output data with new account data
                    $outputContext.Data | Add-Member -MemberType NoteProperty -Name $accountNewProperty.Name -Value $accountNewProperty.Value -Force
                }

                $updateAccountSplatParams = @{
                    Uri         = "$($baseUri)/v1.0/users/$($actionContext.References.Account)"
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
                            Message = "Updated account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old values: $($accountChangedPropertiesObject.oldValues | ConvertTo-Json). New values: $($accountChangedPropertiesObject.newValues | ConvertTo-Json)"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would update account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                }
                #endregion Update account

                break
            }

            "NoChanges" {
                #region No changes
                $actionMessage = "skipping updating account"

                $outputContext.Data = $currentMicrosoftEntraIDAccount

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Skipped updating account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No changes."
                        IsError = $false
                    })
                #endregion No changes

                break
            }

            "MultipleFound" {
                #region Multiple accounts found
                $actionMessage = "updating account"

                # Throw terminal error
                throw "Multiple accounts found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the persons are unique."
                #endregion Multiple accounts found

                break
            }

            "NotFound" {
                #region No account found
                $actionMessage = "updating account"
        
                # Throw terminal error
                throw "No account found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
                #endregion No account found

                break
            }
        }
        #endregion Process
        #endregion Account
    }

    #region Manager
    if ($actionContext.Configuration.updatePrimaryManagerOnUpdate -eq $true) {
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
                $actionMessage = "querying manager Microsoft Entra ID account where [$($managerCorrelationField)] = [$($managerCorrelationValue)]"
    
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
            #region Get previous manager of account
            try {
                # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-list-manager?view=graph-rest-1.0&tabs=http
                $actionMessage = "querying previous manager of account"
        
                $baseUri = "https://graph.microsoft.com/"
                $getPreviousMicrosoftEntraIDManagerAccountSplatParams = @{
                    Uri         = "$($baseUri)/v1.0/users/$($outputContext.AccountReference)/manager"
                    Headers     = $headers
                    Method      = "GET"
                    Verbose     = $false
                    ErrorAction = "Stop"
                }
                $previousMicrosoftEntraIDManagerAccount = $null
                $previousMicrosoftEntraIDManagerAccount = Invoke-RestMethod @getPreviousMicrosoftEntraIDManagerAccountSplatParams
            
                $previousMicrosoftEntraIDManagerAccountId = $previousMicrosoftEntraIDManagerAccount.Id

                Write-Verbose "Queried previous manager of account. Result: $($previousMicrosoftEntraIDManagerAccount | ConvertTo-Json)"
            }
            catch {
                Write-Verbose "No previous manager of account found."
            }
            #endregion Get previous manager of account

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
    
        switch ($actionManager) {
            "Update" {
                #region Set Manager
                # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-post-manager?view=graph-rest-1.0&tabs=http
                $actionMessage = "updating manager for account"
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
                            Message = "Updated manager with [$($currentMicrosoftEntraIDManagerAccountId)] for account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Old value: $($previousMicrosoftEntraIDManagerAccountId | ConvertTo-Json). New value: $($currentMicrosoftEntraIDManagerAccountId | ConvertTo-Json)"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would update manager with [$($currentMicrosoftEntraIDManagerAccountId)] for account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Old value: $($previousMicrosoftEntraIDManagerAccountId | ConvertTo-Json). New value: $($currentMicrosoftEntraIDManagerAccountId | ConvertTo-Json)"
                }
                #endregion Set Manager
    
                break
            }
    
            "MultipleFound" {
                #region Multiple accounts found
                $actionMessage = "updating manager for account"
            
                # Throw terminal error
                throw "Multiple accounts found where [$($managerCorrelationField)] = [$($managerCorrelationValue)]. Please correct this so the persons are unique."
                #endregion Multiple accounts found
            
                break
            }
            
            "NotFound" {
                #region No account found
                $actionMessage = "updating manager for account"
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Skipped updating manager for account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Reason: No account found where [$($managerCorrelationField)] = [$($managerCorrelationValue)]."
                        IsError = $false
                    })
                #endregion No account found
            
                break
            }
    
            "CorrelationValueEmpty" {
                #region No account found
                $actionMessage = "updating manager for account"
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Skipped updating manager for account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Reason: Manager correlation value for [$managerCorrelationField] is empty."
                        IsError = $false
                    })
                #endregion No account found
            
                break
            }
        }
    }
    #endregion Manager
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