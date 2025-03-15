Function Get-ADPrincipalKerberosTokenGroup {
<# 
Comments to 1nTh35h311 (@yossi_sassi)
Version: 1.0.6
v1.0.6 - added sidHistory conversion and indication where sidHistory is present on the account (possible excessive permission/backdoor/etc.)
v1.0.5 - added a check for expired AD accounts + a new optional parameter to display all token groups, including generic default ones
v1.0.4 - fixed an issue where a user wasn't locked out but the lockouttime attribute STILL had a value that prevented the script from running (moved to a WMI query instead)
v1.0.3 - added support for other domains + minor error handling addition
#>
param (
    [cmdletbinding()]
    [Parameter(Position=0,mandatory=$true)]
    [string]$UserName,
    [Parameter(Position=1)]
    [switch]$IncludeDefaultTokenGroups = $false,
    [Parameter(Position=2)]
    [string]$DomainDN = [System.String]::Empty,
    [Parameter(Position=3)]
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
$ds.PropertiesToLoad.AddRange(@("lockouttime","useraccountcontrol","accountExpires","sidHistory"));
$userObj = $ds.FindOne();

# Ensure connection is successful 
if (!$?) 
    {
        Write-Warning "An error occured when connecting to the server. Ensure the domain & DC names are correct.`nQuiting.";
        break
    }

# Get current user's netbios Domain Name
$DomainName = $env:USERDNSDOMAIN;

# enum user token
if ($userObj)
    {
        # Retrieve the accountExpires attribute
        $accountExpires = [int64]$userObj.Properties.accountexpires[0]

        if ($accountExpires -eq 0 -or $accountExpires -eq 9223372036854775807) {
            # "Account never expires"
        } else {
            $expirationDate = [datetime]::FromFileTime($accountExpires);
            if ($expirationDate -lt (Get-Date)) { # skip -> Account expired on: $expirationDate
                $AccountExpired = $true
            } 
            # else - Account is active. Expiration date: $expirationDate
        }

        # get locked out status via WMI
        $AccountLockedWMI  = Get-WmiObject -Namespace "root\cimv2" -Class Win32_UserAccount -Filter "name='$UserName' AND domain='$DomainName'" | select -ExpandProperty LockOut;
        
        if ($AccountLockedWMI -eq $True -xor $Disabled -contains $userObj.Properties.useraccountcontrol -xor $AccountExpired)
        #if ($userObj.Properties.lockouttime -ne $null -xor $Disabled -contains $userObj.Properties.useraccountcontrol)
            {
                Write-Warning "User account is either Locked, Disabled or Expired. Can only enumerate Token Groups for enabled/active users.`nQuiting.";
                break
            }
    }
else
    {
        Write-Warning "Could not find user: $UserName. Make sure you've spelled the name correctly.`nQuiting.";
        break
    }

# Get user context
try {
    $token = [System.Security.Principal.WindowsIdentity]::new($UserName)
} catch {
    # If an error was raised, don't continue enumerating token groups
    Write-Warning "An error occured enumerating token for user: $($UserName.ToUpper()).`nMake sure account is Not Locked out.`nException: $($Error[0].Exception.InnerException.Message)`nQuiting.";
    break
}

# By default, some default generic Groups are excluded from the token, unless the -IncludeDefaultTokenGroups parameter is specified
$ExcludedGroups = 'Everyone','BUILTIN\Users','BUILTIN\Pre-Windows 2000 Compatible Access','BUILTIN\Certificate Service DCOM Access','NT AUTHORITY\NETWORK','NT AUTHORITY\Authenticated Users','NT AUTHORITY\This Organization','Service asserted identity';

# Added function to convert Hex SidHistory to indicate SID coming from SIDHistory
Function Convert-HexSID
{
  [cmdletbinding()]
  param (
  $HexSID
  )
  # Convert into normal array of bytes.
  $strSID = "S-" + $HexSID[0]
  $arrSID = $strSID.Split(" ")
  $Max = $arrSID.Count
  $DecSID = $arrSID[0] + "-" + $arrSID[1] + "-" + $arrSID[8]
  If ($Max -eq 11)
  {
    Return $DecSID
  }
  $Temp1 = [Int64]$arrSID[12] + (256 * ([Int64]$arrSID[13] + (256 * ([Int64]$arrSID[14] + (256 * ([Int64]$arrSID[15]))))))
  $DecSID = $DecSID + "-" + $($Temp1)
  If ($Max -eq 15)
  {
    Return $DecSID
  }
  $Temp2 = [Int64]$arrSID[16] + (256 * ([Int64]$arrSID[17] + (256 * ([Int64]$arrSID[18] + (256 * ([Int64]$arrSID[19]))))))
  $DecSID = $DecSID + "-" + $($Temp2)
  $Temp3 = [Int64]$arrSID[20] + (256 * ([Int64]$arrSID[21] + (256 * ([Int64]$arrSID[22] + (256 * ([Int64]$arrSID[23]))))))
  $DecSID = $DecSID + "-" + $($Temp3)
  If ($Max -lt 24)
  {
    Return $DecSID
  }
  $Temp4 = [Int64]$arrSID[24] + (256 * ([Int64]$arrSID[25] + (256 * ([Int64]$arrSID[26] + (256 * ([Int64]$arrSID[27]))))))
  $DecSID = $DecSID + "-" + $($Temp4)
  Return $DecSID
}

# Get SIDs from Kerberos token
$groupSIDs = $token.Groups;

$EnumeratedGroups = New-Object System.Collections.ArrayList;

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
                        Add-Member -InputObject $Obj -MemberType NoteProperty -Name GroupName -Value $Group.Value -Force;
                        # Get AccountType
                        if ($_.AccountDomainSid -eq $null) {$AccountType="Local"} else {$AccountType="Domain"}
                        Add-Member -InputObject $Obj -MemberType NoteProperty -Name AccountType -Value $AccountType -Force;
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
                Clear-Variable AccountType, Obj, Group
            }
        }

    # Handle SidHistory, IF it applicable
    $sidHistoryValue = Convert-HexSID -HexSID $userObj.Properties.sidhistory -ErrorAction SilentlyContinue;
    if ($sidHistoryValue -ne "---")
        {
                Write-Warning "[!] SidHistory is present on this account.";
                $sidHistoryObj = [adsi]"LDAP://<SID=$sidHistoryValue>";
                $sidHistoryAccountName = "$env:USERDOMAIN\$($sidHistoryObj.Properties.samaccountname)";
                # remove duplicate account from token enum array
                $EnumeratedGroups | foreach {if ($_.GroupName -eq $sidHistoryAccountName) {$DuplicateGroupToRemove = $_}};
        	    $EnumeratedGroups.Remove($DuplicateGroupToRemove) | Out-Null;
                $Obj = New-Object psobject;
                # Ensure we got a valid account (existing domain) for sidHistory. otherwise, display Sid
                if ($sidHistoryAccountName -eq "$env:USERDOMAIN\") 
                    {
                        $sidHistoryAccountName = $sidHistoryValue;
                        $sidHistoryAccountType = "!SidHistory_Unresolved!"
                    }
                else
                    {
                        $sidHistoryAccountType = "!SidHistory!"
                    }

                Add-Member -InputObject $Obj -MemberType NoteProperty -Name GroupName -Value $sidHistoryAccountName -Force;
                Add-Member -InputObject $Obj -MemberType NoteProperty -Name AccountType -Value $sidHistoryAccountType -Force;
                $EnumeratedGroups.Add($Obj) | Out-Null;
        }

    # write output
    Write-Output $EnumeratedGroups | where {$_ -ne $null}
}