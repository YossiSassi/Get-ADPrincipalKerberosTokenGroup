<# 
Comments to 1nTh35h311 (@yossi_sassi)
Version: 1.0.9
v1.0.9 - Added 'fallback' when an account is locked/disabled/expired and Cannot be enumerated for S4U, still - display its non-nested membership (memberof) & sIDHistory, if applicable
v1.0.8 - Added support for Computer accounts PAC Enum, including sID History. Also, a minor display bug fix not removing duplicate group when sIDHistory detected
v1.0.7 - Fixed an issue with multiple entries in sIDHistory + moved to a simpler long-binary/hex sid conversion function + Added a new property to reflect Object Class for sIDHistory + Changed property named to better reflect the content (e.g. samaccountname rather than group name, sIDType rather than accountType)
v1.0.6 - added sidHistory conversion and indication where sidHistory is present on the account (possible excessive permission/backdoor/etc.)
v1.0.5 - added a check for expired AD accounts + a new optional parameter to display all token groups, including generic default ones
v1.0.4 - fixed an issue where a user wasn't locked out but the lockouttime attribute STILL had a value that prevented the script from running (moved to a WMI query instead)
v1.0.3 - added support for other domains + minor error handling addition
#>

Function Get-ADPrincipalKerberosTokenGroup {
param (
    [cmdletbinding()]
    [Parameter(Position=0,mandatory=$true)]
    [string]$SamAccountName,
    [Parameter(Position=1)]
    [switch]$IncludeDefaultTokenGroups = $false,
    [Parameter(Position=2)]
    [string]$DomainDN = [System.String]::Empty,
    [Parameter(Position=3)]
    [string]$DomainController = [System.String]::Empty
)

# default is token enumeration - unless user is disabled/expired/locked
[boolean]$UserCanEnumerateS4U = $true;

# Check if different domain was specified
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

# Updated filter for including Computer accounts as well
$ds.Filter = "(&(|(objectclass=user)(objectclass=computer))(samaccountname=$SamAccountName))";
#$ds.Filter = "(&(objectcategory=person)(objectclass=user)(samaccountname=$UserName))";
$ds.PropertiesToLoad.AddRange(@("lockouttime","useraccountcontrol","accountExpires","sidHistory","memberof"));
$AccountObj = $ds.FindOne();

# Ensure connection is successful 
if (!$?) 
    {
        Write-Warning "An error occured when connecting to the server. Ensure the domain & DC names are correct.";
        break
    }

# Get current netbios Domain Name
$DomainName = $env:USERDNSDOMAIN;

# enum account token
if ($AccountObj)
    {
        # Retrieve the accountExpires attribute
        $accountExpires = [int64]$AccountObj.Properties.accountexpires[0]

        if ($accountExpires -eq 0 -or $accountExpires -eq 9223372036854775807) {
            # "Account never expires"
        } else {
            $expirationDate = [datetime]::FromFileTime($accountExpires);
            if ($expirationDate -lt (Get-Date)) { # skip -> Account expired on: $expirationDate
                $AccountExpired = $true
            } 
            # else - Account is active. Expiration date: $expirationDate
        }

        # Get locked out status via WMI, for a user account only
        if ($SamAccountName -notlike "*$") 
            {
                $AccountLockedWMI  = Get-WmiObject -Namespace "root\cimv2" -Class Win32_UserAccount -Filter "name='$SamAccountName' AND domain='$DomainName'" | select -ExpandProperty LockOut;
            }
        else
            {
                $AccountLockedWMI = $false
            }

        if ($AccountLockedWMI -eq $True -xor [int64]$AccountObj.Properties.useraccountcontrol[0] -band 0x0002 -xor $AccountExpired)
        #if ($userObj.Properties.lockouttime -ne $null -xor $Disabled -contains $userObj.Properties.useraccountcontrol)
            {
                Write-Warning "Account is either Locked, Disabled or Expired. Can only enumerate Token Groups for enabled/active accounts.";
                Write-Host "Displaying non-nested group membership instead (memberof attribute only)" -ForegroundColor Yellow;
                $UserCanEnumerateS4U = $false
            }
    }
else
    {
        Write-Warning "Could not find account: $SamAccountName. Make sure you've spelled the name correctly.";
        break
    }

# function to convert Hex SidHistory to indicate SID coming from SIDHistory
Function Convert-HexSID
{
  [cmdletbinding()]
  param (
  $HexSID
  )
  $sid = New-Object System.Security.Principal.SecurityIdentifier($HexSID, 0);
  return $sid.Value
}

# Set empty group array
$EnumeratedGroups = New-Object System.Collections.ArrayList;

# Begin token enumeration. First - Get account security context
if ($UserCanEnumerateS4U) {
try {
    $token = [System.Security.Principal.WindowsIdentity]::new($SamAccountName)
} catch {
    # If an error was raised, don't continue enumerating token groups
    Write-Warning "An error occured enumerating token for account: $($SamAccountName.ToUpper()).`nMake sure account is Not Locked out.`nException: $($Error[0].Exception.InnerException.Message)";
    break
}

# By default, some default generic Groups are excluded from the token, unless the -IncludeDefaultTokenGroups parameter is specified
$ExcludedGroups = 'Everyone','BUILTIN\Users','BUILTIN\Pre-Windows 2000 Compatible Access','BUILTIN\Certificate Service DCOM Access','NT AUTHORITY\NETWORK','NT AUTHORITY\Authenticated Users','NT AUTHORITY\This Organization','Service asserted identity';

# Get SIDs from Kerberos token
$groupSIDs = $token.Groups;

$groupSIDs | Foreach-Object {
            try {
			        $Obj = New-Object psobject;
                    
                    # Get group name from Sid
                    $Group = ($_).Translate([System.Security.Principal.NTAccount]);
                    
                    # translate the SID to an account name
                    if (!$IncludeDefaultTokenGroups -and $Group -in $ExcludedGroups) { 
                        # skip group (reserved for later use)
                    }
                    
                    else 
                        {
                        # Add group to enumerated groups collection
                        Add-Member -InputObject $Obj -MemberType NoteProperty -Name SamAccountName -Value $Group.Value -Force;
                        # Set Object class to group
                        Add-Member -InputObject $Obj -MemberType NoteProperty -Name ObjectClass -Value "Group" -Force;
                        # Get Sid Type
                        if ($_.AccountDomainSid -eq $null) {$sIDType="Local"} else {$sIDType="Domain"}
                        Add-Member -InputObject $Obj -MemberType NoteProperty -Name sIDType -Value $sIDType -Force;
                        $EnumeratedGroups.Add($Obj) | Out-Null;
                    }
            }
            
            catch 
            { 
			# Output a warning and the corresponding exception
                    Write-Warning ("Could not translate " + $_.Value + ". Reason: " + $_.Exception.Message) 
            }

            finally
            {
                Clear-Variable sIDType, Obj, Group
            }
        }
}
else 
    # user locked, disabled or expired - get memberof only
    {
        $AccountObj.Properties.memberof | ForEach-Object { 
            $GroupName = ([adsi]"LDAP://$_").Properties.samaccountname | Out-String;
            if ($groupname.trim() -ne [System.String]::Empty) {
                $obj = New-Object psobject;
                Add-Member -InputObject $Obj -MemberType NoteProperty -Name SamAccountName -Value "$env:USERDOMAIN\$($GroupName.Trim())" -Force;
                # Set Object class to group
                Add-Member -InputObject $Obj -MemberType NoteProperty -Name ObjectClass -Value "Group" -Force;
                # Set Sid Type to Domain
                Add-Member -InputObject $Obj -MemberType NoteProperty -Name sIDType -Value "Domain" -Force;
                $EnumeratedGroups.Add($Obj) | Out-Null
            }
            Clear-Variable obj, GroupName -ErrorAction SilentlyContinue
        }
    }

# Handle SidHistory, If applicable
if ($AccountObj.Properties.sidhistory -ne $null) 
{
    $sidHistoryValue =  $AccountObj.Properties.sidhistory | ForEach-Object {Convert-HexSID -HexSID $_ -ErrorAction SilentlyContinue}
    Write-Warning "[!] SidHistory is present on this account.";
    $sidHistoryValue | ForEach-Object {
        $sidHistoryCurrentValue = $_;
        $sidHistoryObj = [adsi]"LDAP://<SID=$sidHistoryCurrentValue>";
        $sidHistoryAccountName = "$env:USERDOMAIN\$($sidHistoryObj.Properties.samaccountname)";
        # remove duplicate account from token enum array
        $EnumeratedGroups | foreach {if ($_.SamAccountName -eq $sidHistoryAccountName) {$DuplicateGroupToRemove = $_}};
        $EnumeratedGroups.Remove($DuplicateGroupToRemove) | Out-Null;
        $Obj = New-Object psobject;
        # Ensure we got a valid account (existing domain) for sidHistory. otherwise, display Sid
        if ($sidHistoryAccountName -eq "$env:USERDOMAIN\") 
            {
                $sidHistoryAccountName = $sidHistoryCurrentValue;
                $sidHistoryType = "!SidHistory_Unresolved!"
            }
        else
            {
                $sidHistoryType = "!SidHistory!"
            } 

        # Set object class - ignore if sID invalid / unresolved
        if ($sidHistoryType -eq "!SidHistory_Unresolved!")
            {
                $ObjectClass = "Unresolved"
            }
        else
            {
                $ObjectClass = ($sidHistoryObj.Properties.objectcategory).ToString().split(",")[0].replace("CN=","");
            }
                
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name SamAccountName -Value $sidHistoryAccountName -Force;
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name ObjectClass -Value $ObjectClass -Force;
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name sIDType -Value $sidHistoryType -Force;
        $EnumeratedGroups.Add($Obj) | Out-Null
    }
}

    # write output
    Write-Output $EnumeratedGroups | where {$_ -ne $null}
}