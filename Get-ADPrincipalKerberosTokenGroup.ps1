Function Get-ADPrincipalKerberosTokenGroup {
param (
    [cmdletbinding()]
    [string]$UserName
)
# Get user context
$token = [System.Security.Principal.WindowsIdentity]::new($UserName)

# groups to exclude from the token
$ExcludedGroups = 'Everyone','BUILTIN\Users','BUILTIN\Pre-Windows 2000 Compatible Access','BUILTIN\Certificate Service DCOM Access','NT AUTHORITY\NETWORK','NT AUTHORITY\Authenticated Users','NT AUTHORITY\This Organization','Service asserted identity'

# Get SIDs from Kerberos token
$groupSIDs = $token.Groups;

$groupSIDs | Foreach-Object {
            try {
			# translate the SID to an account name
                        (($_).Translate([System.Security.Principal.NTAccount])) 
            }
            catch { 
			# Output a warning and the corresponding exception
                        Write-Warning ("Could not translate " + $_.Value + ". Reason: " + $_.Exception.Message) 
            }
    } | where {$_ -notin $ExcludedGroups} | select -ExpandProperty value
}
