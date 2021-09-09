#//////Functions
Function Get-OUacl ($ACLlist){
    $MyOUAclArray = New-Object System.Collections.ArrayList

    Foreach ($ACL in $ACLlist){
        $ACLobjectType = if($ACL.ObjectType -eq '00000000-0000-0000-0000-000000000000'){
            "All"
        }ELSE{ 
            $RawGUID = ([guid]$ACL.ObjectType).ToByteArray()
            (Get-ADObject  -Searchbase (Get-ADRootDSE).schemaNamingContext -Filter {schemaIDGUID -eq $RawGuid}).Name
        }
        #if the ACL is not for an object type but a property, search the config partition for a property name 
        if($ACLobjectType -eq $null){
                $ACLobjectTypeFilter = $ACL.ObjectType
                $ACLobjectType = (Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(&(objectClass=controlAccessRight)(rightsguid=$ACLobjectTypeFilter))").Name 
            }      
            
        $ACLinheritedObjectType = if($ACL.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000'){
            "All"
        }ELSE{
            $RawGUID = ([guid]$ACL.InheritedObjectType).ToByteArray()
            (Get-ADObject  -Searchbase (Get-ADRootDSE).schemaNamingContext -Filter {schemaIDGUID -eq $RawGuid}).Name
        }
            
        $ACLentry = $ACL | Select IsInherited,AccessControlType,
            @{Name="ObjectTypeName";Expression={$ACLobjectType}}, @{Name="InheritedObjectTypeName";Expression={$ACLinheritedObjectType}},
            ActiveDirectoryRights, IdentityReference, InheritanceType, InheritanceFlags, PropagationFlags
        [void] $MyOUAclArray.Add($ACLentry)
    }

    Return $MyOUAclArray
    
}

#//////Main
$FinalResults = New-Object System.Data.DataTable
[void]$FinalResults.Columns.AddRange(@('Object','AccessControlType','ObjectTypeName','InheritedObjectTypeName','ActiveDirectoryRights','IdentityReference','MemberCount','Members'))
$OUs = @()
$examinedIdentities = @()
#list of default identities to exlude
$identities = @("NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS","NT AUTHORITY\SYSTEM","BUILTIN\Administrators","NT AUTHORITY\SELF","BUILTIN\Print Operators","S-1-5-32-548")


$F = Get-ADForest

$Fdom = $F.RootDomain
$Ds = $F.Domains
#add domain specific groups to be in exlusion list
$identities += $Fdom.split(".")[0] + "\Enterprise Read-only Domain Controllers"
$identities += $Fdom.split(".")[0] + "\Enterprise Admins"
foreach ($D in $Ds){
    $identities += $D.split(".")[0] + "\Domain Controllers"
    $identities += $D.split(".")[0] + "\Cloneable Domain Controllers"
    $identities += $D.split(".")[0] + "\Domain Admins"
}

#Get all OUs and Containers
foreach ($D in $Ds){
    write-host "Finding OUs and containers in $D"
    #root of domain
    $OUs += Get-ADObject -Filter {objectClass -eq "domain"} -Properties CanonicalName,Name,nTSecurityDescriptor -Server $D #| select CanonicalName,Name,nTSecurityDescriptor
    #AdminSDHolder
    $OUs += Get-ADObject -Filter {name -eq "AdminSDHolder"} -Properties CanonicalName, Name, nTSecurityDescriptor -Server $D #| select CanonicalName,Name,nTSecurityDescriptor
    #containers
    $OUs += Get-ADObject -Filter {objectcategory -eq "container" -or objectcategory -eq "builtinDomain"} -searchscope OneLevel -Properties CanonicalName, Name, nTSecurityDescriptor -Server $D #| select CanonicalName,Name,nTSecurityDescriptor
    #OUs
    $OUs += Get-ADOrganizationalUnit -Filter * -Properties CanonicalName, Name, nTSecurityDescriptor -Server $D #| select CanonicalName,Name,nTSecurityDescriptor
}
$OUs = $OUs | sort canonicalname
$totalOUs = $OUs.Count
write-host "ACLs to examine: $totalOUs"

#time to look at security
for ($i = 0; $i -lt $totalOUs; $i++) {
    $percentcomplete = [math]::Round($i / $totalOUs * 100)
    Write-Progress -Activity "Gathering ACL Information" -Status "$percentcomplete% Complete:" -PercentComplete $percentcomplete -CurrentOperation $OU.CanonicalName

    $OU = $OUs[$i]
    
    #Get a DC name to lookup any items on
    $luDC = $OU.CanonicalName.Split("/")[0]

    $MyACL = $OU | select -ExpandProperty nTSecurityDescriptor | select -ExpandProperty Access
    #get a parent ACL, which if it is the root of the domain is itself 
    if ($OU.ObjectClass -eq "domainDNS"){
        #I'm the root, get my ACL
        $acls = Get-OUacl -ACLlist $MyACL
    #also always get the ACL for AdminSDHolder
    } elseif ($OU.Name -eq "AdminSDHolder") {
        $acls = Get-OUacl -ACLlist $MyACL
    } else {
        #Compare ACLs to parent to see if security changed
        $ParnetAcl = $OUs[$i - 1] | select -ExpandProperty nTSecurityDescriptor | select -ExpandProperty Access
        $comp = Compare-Object $ParnetAcl $MyACL -Property Access
        if($comp.count -gt 0){
            $acls = Get-OUacl -ACLlist $MyACL
        } else {$acls = ""}
    }

    #get details if the ACL changed
    if($acls -ne ""){
        foreach ($acl in $acls){
            #
            #exclude ACEs assigned to default identities
            if ($acl.IdentityReference -notin $identities) {
        
                if ($acl.ObjectTypeName -eq "DS-Replication-Get-Changes-All" -or $acl.ActiveDirectoryRights -match "GenericAll" -or $acl.ActiveDirectoryRights -match "write" -or $acl.ActiveDirectoryRights -match "create" -or $acl.ActiveDirectoryRights -match "Manage Group Policy Link ") {
                    $adobj = ""
                    #lookup any well-known SIDs and translate them
                    if ($acl.IdentityReference -like "S-1-5-32*"){
                        $idlookup = $acl.IdentityReference
                        $lu = Get-ADObject -Filter {objectsid -eq $idlookup} -Properties Name -Server $luDC
                        $finalid = ($luDC.split(".")[0]).toUpper() + "\" + $lu.Name
                    } else { $finalid = $acl.IdentityReference.ToString()}

                    #lookup any members of groups
                    if ($examinedIdentities.identity -contains $finalid) {
                        $mems = $examinedIdentities | where {$_.identity -eq $finalid} | select -expandproperty members
                        $memcount = $examinedIdentities | where {$_.identity -eq $finalid} | select -expandproperty MemberCount
                    } else {
                    $adobj = $finalid.Split("\")[1]
                    if ((Get-ADObject -filter {Name -eq $adobj} -server $luDC).objectClass -eq "Group"){
                        $memlu = Get-ADGroupMember -Identity $adobj -Server $luDC -Recursive | Get-ADObject -Properties canonicalname,name,samaccountname
                        $mems = @()
                        foreach($mem in $memlu){
                            if ($mem.objectClass -eq "user"){$m_id = $mem.canonicalName.split(".")[0] + "\" + $mem.SamAccountName }
                            elseif ($mem.objectClass -eq "computer"){$m_id = $mem.canonicalName.split(".")[0] + "\" + $mem.name }
                            else {$m_id = $mem.CanonicalName}
                            $mems += $m_id
                        }
                        $memcount = $mems.count
                        $mems = $mems -join ","
                    } else { $mems = $acl.IdentityReference.ToString() }
                    $examinedIdentities  += New-Object -TypeName psobject -Property @{identity = $finalid
                                                                            MemberCount = $memcount
                                                                            Members = $mems
                                                                            }
                    }

                    [VOID]$FinalResults.Rows.Add(
                        $OU.CanonicalName,
                        $acl.AccessControlType,
                        $acl.ObjectTypeName,
                        $acl.InheritedObjectTypeName,
                        $acl.ActiveDirectoryRights,
                        $finalid,
                        $memcount,
                        $mems
                    )
            
                }
            }
        }
    }
}


return $FinalResults