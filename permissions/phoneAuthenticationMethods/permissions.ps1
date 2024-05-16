#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-PhoneAuthenticationMethods-List
# List phone authentication methods as permissions
# Please see the Microsoft docs on supported phone types: https://learn.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-get?view=graph-rest-1.0&tabs=http#http-request
# PowerShell V2
#################################################
$outputContext.Permissions.Add(
    @{
        DisplayName    = "phone authentication method - mobile"
        Identification = @{
            Id                            = "3179e48a-750b-4051-897c-87b9720928f7"
            Name                          = "mobile"
            Type                          = "phoneMethod"
            OnlySetWhenEmpty              = $true
            RemoveWhenRevokingEntitlement = $true
        }
    }
)
$outputContext.Permissions.Add(
    @{
        DisplayName    = "phone authentication method - alternateMobile"
        Identification = @{
            Id                            = "b6332ec1-7057-4abe-9331-3d72feddfe41"
            Name                          = "alternateMobile"
            Type                          = "phoneMethod"
            OnlySetWhenEmpty              = $true
            RemoveWhenRevokingEntitlement = $true
        }
    }
)
$outputContext.Permissions.Add(
    @{
        DisplayName    = "phone authentication method - office"
        Identification = @{
            Id                            = "e37fc753-ff3b-4958-9484-eaa9425c82bc"
            Name                          = "office"
            Type                          = "phoneMethod"
            OnlySetWhenEmpty              = $true
            RemoveWhenRevokingEntitlement = $true
        }
    }
)