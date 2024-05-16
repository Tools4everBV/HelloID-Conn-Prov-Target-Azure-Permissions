#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-EmailAuthenticationMethods-List
# List email authentication methods as permissions
# Please see the Microsoft docs on supported amail types: https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-get?view=graph-rest-1.0&tabs=http
# PowerShell V2
#################################################
$outputContext.Permissions.Add(
    @{
        DisplayName    = "email authentication method - email"
        Identification = @{
            Id                            = "3ddfcfc8-9383-446f-83cc-3ab9be4be18f"
            Name                          = "email"
            Type                          = "emailMethod"
            OnlySetWhenEmpty              = $true
            RemoveWhenRevokingEntitlement = $true
        }
    }
)