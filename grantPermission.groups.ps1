#####################################################
# HelloID-Conn-Prov-Target-Azure-Permissions-GrantPermission-Group
#
# Version: 2.0.0 | new-powershell-connector
#####################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# The accountReference object contains the Identification object provided in the create account call
$aRef = $actionContext.References.Account 

# The permissionReference object contains the Identification object provided in the retrieve permissions call
$pRef = $actionContext.References.Permission

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

try {
    # Get current Azure AD account
    try {
        if ($null -eq $aRef) {
            throw "No Account Reference found in HelloID"
        }

        $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

        Write-Verbose "Querying Azure AD account with id $($aRef)"
        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = "$baseUri/v1.0/users/$($aRef)"
            Headers = $headers
            Method  = 'GET'
        }
        $currentAccount = $null
        $currentAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false

        if ($null -eq $currentAccount.id) {
            throw "No User found in Azure AD with id $($aRef)"
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

        if ($auditErrorMessage -Like "No User found in Azure AD with id $($aRef)" -or $auditErrorMessage -Like "*(404) Not Found.*") {
            if (-Not($actionContext.DryRun -eq $true)) {
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "No Azure AD account found with id $($aRef). Possibly deleted."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: No Azure AD account found with id $($aRef). Possibly deleted."
            }        
        }
        else {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "GrantPermission"
                    Message = "Error querying Azure AD account with id $($aRef). Error Message: $auditErrorMessage"
                    IsError = $True
                })
        }
    }

    # Grant AzureAD Groupmembership
    if (-NOT($null -eq $currentAccount.id)) {
        try {
            Write-Verbose "Granting permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"

            $bodyAddPermission = [PSCustomObject]@{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($aRef)"
            }
            $body = ($bodyAddPermission | ConvertTo-Json -Depth 10)

            $splatWebRequest = @{
                Uri     = "$baseUri/v1.0/groups/$($pRef.id)/members/`$ref"
                Headers = $headers
                Method  = 'POST'
                Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }
            
            if (-Not($actionContext.DryRun -eq $true)) {
                $addPermission = Invoke-RestMethod @splatWebRequest -Verbose:$false
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "Successfully granted permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would grant permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"
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
            
            # Since the error message for adding a user that is already member is a 400 (bad request), we cannot check on a code or type
            # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
            if ($auditErrorMessage -like "*One or more added object references already exist for the following modified properties*") {
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "User '$($currentAccount.userPrincipalName)' is already a member of the group '$($pRef.Name)'. Skipped grant of permission to group '$($pRef.Name) ($($pRef.id))' for user '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"
                        IsError = $false
                    }
                )
            }
            else {
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "Error granting permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'. Error Message: $auditErrorMessage"
                        IsError = $True
                    })
            }
        }
    }
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}