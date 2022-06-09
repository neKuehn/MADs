FUNCTION Invoke-ReplicateDirectoryChanges{
    <#
    .SYNOPSIS
    Invoke-ReplicateDirectoryChanges allows you to gather information out of Active Directory using Directory Replication instead of normal LDAP searches.

    Author: Eric Kuehn
        
    .DESCRIPTION
    This leverages the Replicate Directory Changes right to harvest data out of Active Directory.  This can be used to gather information out of confidential attributes. Backlinked and constructed attributes (such as memberOf and canonicalName) cannot be pulled as these aren't real attributes.  The script returns a collection of objects, so it can be sent through the pipeline or into a variable.  Thanks to Ondrej Sevecek's script that demonstrated how to use the LDAP DirSync class in PowerShell https://www.sevecek.com/EnglishPages/Lists/Posts/Post.aspx?ID=80
    
    .PARAMETER attributesToGet
    Enter which attributes you want returned in the dataset. By default, it will supply sAMAccountName and cn.

    .PARAMETER LDAPfilter
    This will limit what type of object is included in the dataset. This should be formatted as an LDAP query. I.E. "(objectCategory=user)"

    .PARAMETER DomainController
    This is the IP address or name of the Domain Controller you want to connect to. If not supplied, the script will attempt to connect to the user's Domain Controller or prompt for a DC if the device is not in a domain.

    .PARAMETER DomainName
    The full DNS name of the Domain being searched. I.e 'lab.pvt'.  If not specified, the script will try to dtermine the domain of the current user or prompt if it can't find one.

    .PARAMETER Credentials
    If used, the script will prompt for credentials to use to connect to the Domain Controller.

    .PARAMETER LDAPs
    Connect to the Domain Controller over LDAPs instead of LDAP.

    .EXAMPLE
    Invoke-ReplicateDirectoryChanges
    Attempts to use the current credentials and machine information to connect to a Domain Controller, query all AD objects, and return the distinguishedName, sAMAccountName, and name attributes.

    .EXAMPLE
    Invoke-ReplicateDirectoryChanges -DomainController 172.22.204.194 DomainName 'lab.pvt' -LDAPfilter '(objectCategory=user)' -attributesToGet 'samaccountname','unixUserPassword' -Credentials
    After prompting for credentials, it will connect to 172.22.204.194 and search for user accounts in the lab.pvt domain, and return the distinguishedName, sAMAccountName, and unixUserPassword attributes

    .NOTES
    The credentials being used with this script must have the "Replicating Directory Changes" or "Replicating Directory Changes - All" rights.  This script cannot return password hashes (userPassword, unicodePwd, or ntPwdHistory) out of AD as they are not exposed to LDAP, regardles of rights.

    #>

    #///////Accept the input information for the script
    [CmdletBinding()]
    Param(
        [PARAMETER(Mandatory=$False)][string]$LDAPfilter,    
        [PARAMETER(Mandatory=$False)][string[]] $attributesToGet, 
        [PARAMETER(Mandatory=$False)][string]$DomainController,
        [PARAMETER(Mandatory=$false)][string]$DomainName,
        [PARAMETER(Mandatory=$False)][switch]$Credentials,
        [PARAMETER(Mandatory=$False)][switch]$LDAPs
        #[PARAMETER(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    #Create some global variables
    $ldapEntries = @()
    $translatedObjects = @()
    [string] $userID = ''
    [void] ([System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices.Protocols'))

    if (!$DomainController) {
        if (!$env:userdnsdomain) {
            # not joined to domain or user not logged in with domain account, prompt for DC
            $DomainController = Read-Host -Prompt 'Domain Controller DNS name or IP Address'
        } else {
            $DomainController = ($env:logonserver).replace('\','') + '.' + $env:userdnsdomain
        }
    }
    
    if (!$DomainName) {
        switch (!$env:userdnsdomain) {
            #do some funky removal of quotes and single quotes from entered data
            $true {$DomainName = (Read-Host -Prompt 'Full DNS name of the Domain').replace('"','').replace("'","")}
            #build the root DN from the domain DNS name
            $false {$DomainName = $env:userdnsdomain}
        }     
    }
    $rootDN = 'dc=' + $DomainName.replace('.',',dc=')

    if (!$LDAPfilter){
        $LDAPfilter = (Read-Host -Prompt 'LDAP filter for the query').replace('"','').replace("'","")
     }

    #handle using supplied credentials or passthrough authentication
    if (!$Credentials -and $env:userdnsdomain){
        $userID = $env:userdnsdomain + '\' + $env:username
        [DirectoryServices.Protocols.LdapConnection] $ldapConn = New-Object DirectoryServices.Protocols.LdapConnection($DomainController)
        $ldapConn.AuthType = [DirectoryServices.Protocols.AuthType]::Kerberos
    } else {
        #Prompt for AD Domain Name and Credentials
        $Creds = Get-Credential -Credential Domain\PW
        $userID = $Creds.UserName
        [DirectoryServices.Protocols.LdapConnection] $ldapConn = New-Object DirectoryServices.Protocols.LdapConnection($DomainController,$Creds)
        $ldapConn.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
    }

    #set config for LDAPs or have the regular LDAP use Kerberos Encryption (if possible)
    if (($LDAPs) -and ($DomainController -notlike '*:636')) { $DomainController = '{0}:636' -f $DomainController }
    if (-not $LDAPs) {
        $ldapConn.SessionOptions.Sealing = $true
    } else {
        $ldapConn.SessionOptions.SecureSocketLayer = $true
    }

    #Return some generic attributes if none have been entered
    if (!$attributesToGet){
        $attributesToGet = ('samaccountname', 'name')
    }

    #Give some feedback to the user, letting them know it is doing something
    Write-Host "Connecting to $DomainController as $userID"
    Write-Host " - LDAP search root: $rootDN"
    Write-Host " - LDAP search filter: $LDAPfilter"
    Write-Host " - Returning LDAP attributes: DistinguishedName $attributesToGet"
    Write-Host

    #set some config information for the LDAP request
    [DirectoryServices.Protocols.SearchRequest] $ldapRequest = New-Object DirectoryServices.Protocols.SearchRequest($rootDN, $LDAPfilter, 'SubTree', $attributesToGet)
    [byte[]] $dirSyncCookie = $null
    [DirectoryServices.Protocols.DirSyncRequestControl] $dirSyncCtr = New-Object DirectoryServices.Protocols.DirSyncRequestControl($dirSyncCookie, [DirectoryServices.Protocols.DirectorySynchronizationOptions]::None, [Int32]::MaxValue)
    [void] $ldapRequest.Controls.Add($dirSyncCtr)
    [bool] $moreProcessingRequired = $false
    [int] $dirsyncBatch = 0

    #Connect to LDAP, do a Directory Sync request for information, and continue to get all objects meeting the search criteria
    do {
        do {
            [DirectoryServices.Protocols.SearchResponse] $ldapResponse = $null
            $ldapResponse = $ldapConn.SendRequest($ldapRequest)
            #put in logic to know let people know it is paging
            $dirsyncBatch += 1 
            if ($dirsyncBatch -gt 0) {
                $ldapResCode = $ldapResponse.ResultCode
                $ldapResCount = $ldapResponse.Entries.Count
                Write-Host "DirSync Part $dirsyncBatch : $ldapResCode | $ldapResCount Entries"
            }

            foreach ($oneEntry in $ldapResponse.Entries){
                $ldapEntries += $oneEntry
            }

            $moreProcessingRequired = $false

            if (-not ([object]::Equals($ldapResponse, $null))) {
                foreach ($oneLdapResponseControl in $ldapResponse.Controls) {
                    if ($oneLdapResponseControl -is [DirectoryServices.Protocols.DirSyncResponseControl]) {
                        [DirectoryServices.Protocols.DirSyncResponseControl] $dirSyncCtrResponse = [DirectoryServices.Protocols.DirSyncResponseControl] $oneLdapResponseControl
                        $dirSyncCtr.Cookie = $dirSyncCtrResponse.Cookie
                        $moreProcessingRequired = $dirSyncCtrResponse.MoreData
                        break
                    }
                }
            }
        } while ($moreProcessingRequired)
    } while ($ldapResponse.Entries.Count -gt 0)

    foreach ($ldapEntry in $ldapEntries){
        #build the base object
        $tranObj = New-Object PSObject -property @{
            'dn'= $ldapEntry.DistinguishedName
            }
        #add the different properties of the object based on our filter
        foreach ($attribute in $attributesToGet) {
            $tranObj | Add-Member -MemberType NoteProperty -Name $attribute -Value $null
        }
    
        foreach ($Att in $ldapEntry.Attributes.GetEnumerator()) {
            if ($Att.Name -in  $attributesToGet) {
                
                $attName = $Att.key
    
                $attByte = $Att.value | select-object
                if ($attByte -eq $null){
                    $data = ""
                } ELSE {
                    #add support for multivalue
                    if ($attByte.gettype().name -eq 'byte[]') {
                        #this is a single value attribute
                        $data = ""
                        $data = [System.Text.Encoding]::ASCII.GetString($attByte)
                    } ELSE {
                        #this is a multivalue attribute
                        $data = @()
                        foreach ($mvAttByte in $attByte) {
                            $mvdata = [System.Text.Encoding]::ASCII.GetString($mvAttByte)
                            $data += $mvdata
                        }
                    }
                    
                }
                
                $tranObj.$attName = $data
    
            }
    
        }
        $translatedObjects += $tranObj
    }

    return $translatedObjects
}