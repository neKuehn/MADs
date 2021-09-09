#//////Functions
FUNCTION Get-AdminGroupMembers($Group, $DomainName){
    
    $Mems = Get-ADGroupMember -Identity $Group -Server $DomainName -Recursive 
    
    Foreach ($mem in $Mems){
        if ($mem.objectClass -eq "user"){
            $adobj = $mem | Get-ADUser -Properties AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,mail,MemberOf,PasswordNotRequired,SamAccountName,ServicePrincipalNames,canonicalName
            $act = ($adobj.canonicalName.split("."))[0] + "\" + $adobj.SamAccountName
        } elseif ($mem.objectClass -eq "computer"){
            $adobj = $mem | Get-ADComputer -Properties AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,mail,MemberOf,PasswordNotRequired,SamAccountName,ServicePrincipalNames,canonicalName
            $act = ($adobj.canonicalName.split("."))[0] + "\" + $adobj.name
        } else {
            #If this is not a user or computer, notate it
            $adobj = $mem | Get-ADObject -Properties canonicalName
            
            [VOID]$FinalResults.Rows.Add(
            $DomainName,
            $Group,
            $adobj.canonicalname,
            'unkown',
            'unkown',
            'unkown',
            'unkown',
            'unkown'
            )
            return
        }

        #do some general calcs before adding to the table
        $grpCt = $adobj.memberOf.count - 1
        if ($adobj.ServicePrincipalNames.count -gt 0){$kerberoastable = "True"}else{$kerberoastable = "False"}
        
        [VOID]$FinalResults.Rows.Add(
        $DomainName,
        $Group,
        $act,
        $adobj.mail,
        $grpCt,
        $adobj.AllowReversiblePasswordEncryption,
        $kerberoastable,
        $adobj.DoesNotRequirePreAuth
        )
    }
}


FUNCTION Get-DomainFromDistinguishedName($DN){
    $DNDomDNS =''
    $DNparts = $DN -split ","
    Foreach ($arrPart in $DNparts) {
        If ($arrPart -like 'dc=*'){
            $apDns = $arrPart -Replace "DC=","."
            $DNDomDNS = $DNDomDNS + $apDns
        }
    }
    $DNDomDNS = $DNDomDNS.TrimStart(".")
    Return $DNDomDNS
}

#///// Main
$FinalResults = New-Object System.Data.DataTable
[void]$FinalResults.Columns.AddRange(@('Domain','Group','Account','email','OtherGroupCt','ClearTextPwd','kerberoastable','AESrepable'))

$GroupsToCheck = ("Domain Admins","Administrators","Backup Operators","Server Operators","Account Operators","Group Policy Creator Owners")

$F = Get-ADForest

$Fdom = $F.RootDomain
$Ds = $F.Domains
$TotalGrps = ($GroupsToCheck.count * $Ds.Count) + 1

Write-Host ("Total Groups to Check: $TotalGrps")

Get-AdminGroupMembers -Group "Enterprise Admins" -DomainName $Fdom
Get-AdminGroupMembers -Group "Schema Admins" -DomainName $Fdom

$i = 0
Foreach ($D in $Ds){
    foreach ($grp in $GroupsToCheck){
        $percentcomplete = [math]::Round($i / $TotalGrps * 100)
        Write-Progress -Activity "Gathering Group Membership Information" -Status "$percentcomplete% Complete:" -PercentComplete $percentcomplete -CurrentOperation "$D\$grp"
        Get-AdminGroupMembers -Group $grp -DomainName $D
        $i++
    }
}

Return $FinalResults

