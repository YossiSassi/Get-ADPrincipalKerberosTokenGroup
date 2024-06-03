Function Get-ADPrincipalKerberosTokenGroup {
<# 
Comments to 1nTh35h311 @yossi_sassi
Version: 1.0.3
v1.0.3 - added support for other domains + minor error handling addition
#>
param (
    [cmdletbinding()]
    [Parameter(Position=0,mandatory=$true)]
    [string]$UserName,
    [Parameter(Position=1)]
    [string]$DomainDN = [System.String]::Empty,
    [Parameter(Position=2)]
    [string]$DomainController = [System.String]::Empty
)

# first, check that user is Not disabled/lockedout (if True, then no use to even try to perform the check, cannot enum token)
$Disabled = @();
$Disabled += "514","546","66050";

if ($DomainDN -ne [System.String]::Empty)
    {
        if ($DomainController -eq [System.String]::Empty)
            {
                $DomainController = Read-Host "DomainController must be given when specifying a Domain DN.`nPlease enter the name of a DC in domain $DomainDN"
            }
        $de = [adsi]"LDAP://$DomainController/$DomainDN";
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
    }
else
    {
        $ds = New-Object System.DirectoryServices.DirectorySearcher
    }

$ds.Filter = "(&(objectcategory=person)(objectclass=user)(samaccountname=$UserName))";
$userObj = $ds.FindOne()

# Ensure connection is successful 
if (!$?) 
    {
        Write-Warning "An error occured when connecting to the server. Ensure the domain & DC names are correct.`nQuiting.";
        break
    }

# enum user token
if ($userObj)
    {
        if ($userObj.Properties.lockouttime -ne $null -xor $Disabled -contains $userObj.Properties.useraccountcontrol)
            {
                Write-Warning "User account is either Locked or Disabled. Can only enumerate Token Groups for enabled/active users.`nQuiting.";
                break
            }
    }
else
    {
        Write-Warning "Could not find user: $UserName. Make sure you've spelled the name correctly.`nQuiting.";
        break
    }

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