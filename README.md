<b> Update: Get-ADPrincipalKerberosTokenGroup now supports discovery of SidHistory in PAC<br>
(note: sidHistory can be a group or a user, any AD account with a Sid, from any domain).</b><br><br>
Group membership plays a pivotal role in Access Control and permissions assignments to object, shaping the *effective access/permissions to objects*.<br>
Active Directory tools show and relate to the *direct* group membership, e.g. memberOf attribute. yet what if a user is a member of a group, and that group is a member of two other groups? all those group SIDs are effectively enumerated and added to the user's token/PAC at logon.<br><br>
When a user logs in, the *nested* / recursive group membership is calculated into the token, or Kerberos PAC in Active Directory (all group SIDs, including of groups of groups).<br><br>
This powershell implementation of PAC enumeration gets this information for any user in the domain, as long as they are enabled (& not locked out).<br>
Does not require special privileges. No dependencies.
