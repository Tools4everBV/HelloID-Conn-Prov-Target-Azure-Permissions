#####################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Resources-Teams
# Creates teams dynamically based on HR data
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

#region team
# Make sure the resourceContext data is unique. Fill in the required fields after -unique
# Example: department
$resourceData = $resourceContext.SourceData | Select-Object -Unique ExternalId, DisplayName
# Example: title
# $resourceData = $resourceContext.SourceData | Select-Object -Unique ExternalId, Name
# Define correlation
$correlationField = "displayName"
$correlationValue = "" # Defined later in script

# Hardcoded Object ID of Azure AD User to set as owner of team
$ownerAccountId = "7dcbb7e7-ae5f-499e-b9d4-ad80c6eb097c"
#endRegion team

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

    #region Get Microsoft Entra ID Teams
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/teams-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Teams"

    $microsoftEntraIDTeams = [System.Collections.ArrayList]@()
    do {
        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDTeamsSplatParams = @{
            Uri         = "$($baseUri)/v1.0/teams?`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDTeamsResult.'@odata.nextLink')) {
            $getMicrosoftEntraIDTeamsSplatParams["Uri"] = $getMicrosoftEntraIDTeamsResult.'@odata.nextLink'
        }

        $getMicrosoftEntraIDTeamsResult = $null
        $getMicrosoftEntraIDTeamsResult = Invoke-RestMethod @getMicrosoftEntraIDTeamsSplatParams
    
        if ($getMicrosoftEntraIDTeamsResult.Value -is [array]) {
            [void]$microsoftEntraIDTeams.AddRange($getMicrosoftEntraIDTeamsResult.Value)
        }
        else {
            [void]$microsoftEntraIDTeams.Add($getMicrosoftEntraIDTeamsResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDTeamsResult.'@odata.nextLink'))

    # Group on correlation property to check if group exists (as correlation property has to be unique for a group)
    $microsoftEntraIDTeamsGrouped = $microsoftEntraIDTeams | Group-Object $correlationField -AsHashTable -AsString

    Write-Information "Queried Microsoft Entra ID Teams. Result count: $(($microsoftEntraIDTeams | Measure-Object).Count)"
    #endregion Get Microsoft Entra ID Teams

    foreach ($resource in $resourceData) {
        $actionMessage = "querying team for resource: $($resource | ConvertTo-Json)"
 
        # Example: department_<departmentname>
        $teamName = "department_" + $resource.DisplayName

        # Example: title_<titlename>
        # $teamName = "title_" + $resource.Name

        # Sanitize team name, e.g. replace " - " with "_" or other sanitization actions 
        $teamName = Get-SanitizedGroupName -Name $teamName

        $correlationValue = $teamName


        $correlatedResource = $null
        $correlatedResource = $microsoftEntraIDTeamsGrouped["$($correlationValue)"]
        
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
                #region Create team
                # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/team-post?view=graph-rest-1.0&tabs=http
                $actionMessage = "creating team for resource: $($resource | ConvertTo-Json)"

                $createTeamBody = @{
                    "template@odata.bind" = "https://graph.microsoft.com/v1.0/teamsTemplates('standard')"
                    displayName           = $teamName
                    description           = "$($resource.ExternalId)"
                    visibility            = "Private"

                    members               = [System.Collections.ArrayList]@()
                }

                if (-not[string]::IsNullOrEmpty($ownerAccountId)) {
                    [void]$createTeamBody.members.add(
                        @{
                            "@odata.type"     = "#microsoft.graph.aadUserConversationMember"
                            roles             = @(
                                "owner"
                            )
                            "user@odata.bind" = "https://graph.microsoft.com/v1.0/users('$ownerAccountId')"
                        }
                    )
                }

                $baseUri = "https://graph.microsoft.com/"
                $createGroupSplatParams = @{
                    Uri         = "$($baseUri)/v1.0/teams"
                    Headers     = $headers
                    Method      = "POST"
                    Body        = ($createTeamBody | ConvertTo-Json -Depth 10)
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "SplatParams: $($createGroupSplatParams | ConvertTo-Json)"

                    $createdTeam = Invoke-RestMethod @createGroupSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "CreateResource"
                            Message = "Created team with name [$($teamName)]."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would create team with name [$($teamName)] for resource: $($resource | ConvertTo-Json)."
                }
                #endregion Create team

                break
            }

            "CorrelateResource" {
                #region Correlate team
                $actionMessage = "correlating to team"

                Write-Verbose "Correlated to team with id [$($correlatedResource.id)] on [$($correlationField)] = [$($correlationValue)]."
                #endregion Correlate team

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
