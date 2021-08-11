Function Get-ADPrincipalKerberosTokenGroup {
param (
    [cmdletbinding()]
    [string]$UserName
)

# Get user context
$token = [System.Security.Principal.WindowsIdentity]::new($UserName);

# Groups to exclude from the token
$ExcludedGroups = 'Everyone','BUILTIN\Users','BUILTIN\Pre-Windows 2000 Compatible Access','BUILTIN\Certificate Service DCOM Access','NT AUTHORITY\NETWORK','NT AUTHORITY\Authenticated Users','NT AUTHORITY\This Organization','Service asserted identity';

# Get SIDs from Kerberos token
$groupSIDs = $token.Groups;

$EnumeratedGroups = @();

$groupSIDs | Foreach-Object {
            try {
			        $Obj = New-Object psobject;
                    
                    # Get group name from Sid
                    $Group = ($_).Translate([System.Security.Principal.NTAccount]);
                    
                    # translate the SID to an account name
                    if ($Group -notin $ExcludedGroups) {
                        Add-Member -InputObject $Obj -MemberType NoteProperty -Name GroupName -Value $Group.Value -Force;
                        # Get AccountType
                        if ($_.AccountDomainSid -eq $null) {$AccountType="Local"} else {$AccountType="Domain"}
                        Add-Member -InputObject $Obj -MemberType NoteProperty -Name AccountType -Value $AccountType -Force;
                        $EnumeratedGroups += $Obj;
                    }
            }
            
            catch 
            { 
			# Output a warning and the corresponding exception
                    Write-Warning ("Could not translate " + $_.Value + ". Reason: " + $_.Exception.Message) 
            }

            finally
            {
                Clear-Variable AccountType, Obj, Group;
            }
        }

    # write output
    Write-Output $EnumeratedGroups | where {$_ -ne $null}
}