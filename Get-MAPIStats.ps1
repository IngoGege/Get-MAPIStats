<#
        .SYNOPSIS

        Created by: https://ingogegenwarth.wordpress.com/
        Version:    42 ("What do you get if you multiply six by nine?")
        Changed:    12.01.2017

        .DESCRIPTION

        This script allows you to parse logs from MAPI Client Access folder across multiple servers, without the need to copy them locally.

        .PARAMETER UserID

        Filter for a given user. It's taken from the last part of the LegacyExchangeDN.

        .PARAMETER UserIDs

        Filter for muliple users. Just define multiple users comma seperated.

        .PARAMETER StartDate

        Filter by date. The fomart is yyMMddHH. The default is the current date in the format yyMMdd.

        .PARAMETER EndDate

        Filter by date. The fomart is yyMMddHH. The default is the current date in the format yyMMdd.

        .PARAMETER Logparser

        Define the path to LogParser.exe. The default is "${env:ProgramFiles(x86)}\Log Parser 2.2\LogParser.exe".

        .PARAMETER ADSite

        Search for Exchange servers in one or multiple sites. The default is the current site from the the script is running. You can define multiple sites comma seperated.

        .PARAMETER Outpath

        Define where the CSV files will be stored. Default is "$env:temp"

        .PARAMETER ConcurrentConnections

        Switch to query number of concurrent connections within the given ConcurentIntervall.

        .PARAMETER ConcurrentIntervall

        Define the intervall of the query ConcurrentConnections in seconds. Default is 900 seconds=15 minutes.

        .PARAMETER ClientReport

        Creates areport of all unique user-agents and the number of hits for each.
        Note: This is NOT the unique number of users.

        .PARAMETER ErrorReport

        Creates a report of all errors.

        .PARAMETER E16CU4orLater
        With Exchange 2016CU4 the path and design of these logfiles have been changed. With this switch you can query these.

        .PARAMETER Localpath

        if you have already collected log files, you can define the path to those in order to have them analyzed

        .EXAMPLE

        .\Get-MAPIStats.ps1 -UserID Ingo -Outpath $env:USERPROFILE\Documents

        .\Get-MAPIStats.ps1 -ConcurrentConnections -Outpath $env:USERPROFILE\Documents

        .\Get-MAPIStats.ps1 -ErrorReport -Outpath $env:USERPROFILE\Documents

        .\Get-MAPIStats.ps1 -UserID Ingo -StartDate 16111506 -EndDate 16111508

        .\Get-MAPIStats.ps1 -UserID Ingo -SpecifiedServers server1,server2

        .NOTES

        For performance reasons don't run the script against multiple sites, which are connected by WAN.

#>

[CmdletBinding(DefaultParameterSetName = 'ALL')]
param(

    [parameter( ParameterSetName='ALL')]
    [parameter( ParameterSetName='USER')]
    [parameter(Mandatory=$false, Position=0)]
    [string]$UserID,

    [parameter( ParameterSetName='ALL')]
    [parameter( ParameterSetName='USERS')]
    [parameter(Mandatory=$false, Position=1)]
    [array]$UserIDs,

    [parameter( Mandatory=$false, Position=2)]
    [int]$StartDate="$((get-date).ToString('yyMMdd'))",

    [parameter( Mandatory=$false, Position=3)]
    [int]$EndDate="$((get-date).ToString('yyMMdd'))",

    [parameter( Mandatory=$false, Position=4)]
    [ValidateScript({if (Test-Path -Path $_ -PathType leaf) {$True} else {Throw 'Logparser could not be found!'}})]
    [string]$Logparser="${env:ProgramFiles(x86)}\Log Parser 2.2\LogParser.exe",

    [parameter( Mandatory=$false, Position=5)]
    [string[]]$ADSite="([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name",

    [parameter( Mandatory=$false, Position=6)]
    [ValidateScript({if (Test-Path -Path $_ -PathType container) {$True} else {Throw ('{0} is not a valid path!' -f $_)}})]
    [string]$Outpath = $env:temp,

    [parameter( ParameterSetName='ALL')]
    [parameter( ParameterSetName='USER')]
    [parameter( ParameterSetName='USERS')]
    [parameter( ParameterSetName='Concurrent')]
    [parameter( Mandatory=$false, Position=7)]
    [switch]$ConcurrentConnections,

    [parameter( ParameterSetName='USER')]
    [parameter( ParameterSetName='USERS')]
    [parameter( ParameterSetName='Concurrent')]
    [parameter( Mandatory=$false, Position=7)]
    [int]$ConcurrentIntervall= '900',

    [parameter( ParameterSetName='ClientReport')]
    [parameter( Mandatory=$false, Position=8)]
    [switch]$ClientReport,

    [parameter( ParameterSetName='ErrorReport')]
    [parameter( Mandatory=$false, Position=9)]
    [switch]$ErrorReport,

    [parameter( Mandatory=$false, Position=10)]
    [array]$SpecifiedServers,

    [parameter( ParameterSetName="USER")]
    [parameter( ParameterSetName="USERS")]
    [parameter( ParameterSetName='ErrorReport')]
    [parameter( Mandatory=$false, Position=11)]
    [switch]$E16CU4orLater = $true,

    [parameter( Mandatory=$false, Position=12)]
    [ValidateScript({if (Test-Path -Path $_ -PathType container) {$True} else {Throw "$_ is not a valid path!"}})]
    [string]$Localpath
)

Begin{


    # check for elevated PS
    if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] 'Administrator'))
    {
        Write-Warning -Message "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
        break
    }

    # function to get the Exchangeserver from AD site
    function GetExchServer {
        [CmdLetBinding()]
        #http://technet.microsoft.com/en-us/library/bb123496(v=exchg.80).aspx on the bottom there is a list of values
        param([array]$Roles,[string[]]$ADSites
        )
        Process {
            $valid = @('2','4','16','20','32','36','38','54','64','16385','16439')
            foreach ($Role in $Roles){
                if (!($valid -contains $Role)) {
                    Write-Output -InputObject 'Please use the following numbers: MBX=2,CAS=4,UM=16,HT=32,Edge=64 multirole servers:CAS/HT=36,CAS/MBX/HT=38,CAS/UM=20,E2k13 MBX=54,E2K13 CAS=16385,E2k13 CAS/MBX=16439'
                    return
                }
            }
            function GetADSite {
                [CmdletBinding()]
                param([string]$Name)
                if ($null -eq $Name) {
                    [string]$Name = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name
                }
                $FilterADSite = "(&(objectclass=site)(Name=$Name))"
                $RootADSite= ([ADSI]'LDAP://RootDse').configurationNamingContext
                $SearcherADSite = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ([ADSI]"LDAP://$RootADSite")
                $SearcherADSite.Filter = "$FilterADSite"
                $SearcherADSite.pagesize = 1000
                $ResultsADSite = $SearcherADSite.FindOne()
                $ResultsADSite
            }
            $Filter = '(&(objectclass=msExchExchangeServer)(|'
            foreach ($ADSite in $ADSites){
                $Site=''
                $Site = GetADSite -Name $ADSite
                if ($null -eq $Site) {
                    Write-Verbose -Message "ADSite $($ADSite) could not be found!"
                }
                else {
                    Write-Verbose -Message "Add ADSite $($ADSite) to filter!"
                    $Filter += "(msExchServerSite=$((GetADSite -Name $ADSite).properties.distinguishedname))"
                }
            }
            $Filter += ')(|'
            foreach ($Role in $Roles){
                $Filter += "(msexchcurrentserverroles=$Role)"
            }
            $Filter += '))'
            $Root= ([ADSI]'LDAP://RootDse').configurationNamingContext
            $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ([ADSI]"LDAP://$Root")
            $Searcher.Filter = "$Filter"
            $Searcher.pagesize = 1000
            $Results = $Searcher.FindAll()
            if ('0' -ne $Results.Count) {
                $Results
            }
            else {
                Write-Verbose -Message 'No server found!'
            }
        }
    }

    # function to build string for Logparser if multiple userIDs or deviceIDs given
    function buildstring {
        [CmdletBinding()]
        param(
            [array]$strings
        )
        foreach ($string in $strings) {
            $temp += "'" + $string + "';"
        }
        $temp.TrimEnd(';').ToLower()
    }

    # function to build string for stamp if multiple users given
    function buildstamp {
        [CmdletBinding()]
        param(
            [array]$strings
        )
        foreach ($string in $strings) {
            $temp += $string + '_'
        }
        $temp.ToLower()
    }

    if ($E16CU4orLater) {
        $LogFolder = '\Logging\MapiHttp\Mailbox'
    }
    else {
        $LogFolder = '\Logging\MAPI Client Access'
    }

    # set variables
    [string]$FolderPath = $null
    [array]$LogFiles = $null
    [array]$TempLogs = $null
    [string]$LogsFrom = $null

    #Get Server and folders
    if (!($Localpath)) {
        # get CAS servers
        if ($E16CU4orLater) {
            [array]$Servers += GetExchServer -Role 16385,16439 -ADSites $ADSite | Where-Object {$_.Properties.versionnumber -ge '1942061725'}
        }
        else{
            [array]$Servers += GetExchServer -Role 16385,16439 -ADSites $ADSite | Where-Object {$_.Properties.versionnumber -lt '1942061725'}
        }
        if ($SpecifiedServers) {
            $Servers = $Servers | Where-Object {$SpecifiedServers -contains $_.Properties.name}
        }
        if ($Servers) {
            Write-Output -InputObject 'Found the following Exchange 2013 servers:', $($Servers | foreach-Object{$_.Properties.name})
            foreach ($Server in $Servers) {
                [array]$TempPath += '\\' + $Server.Properties.name + '\' + ($Server.Properties.msexchinstallpath -as [string]).Replace(':','$') + $LogFolder
            }
        }
        else {
            Write-Output -InputObject 'No server found!'
            break
        }
    }
    else {
        Write-Output -InputObject 'Using the following path:', $Localpath
        [array]$TempPath = $Localpath
        $ADSite = 'localfiles'
    }

    # validate all folderpath
    foreach ($FolderPath in $TempPath) {
        if (Test-Path -LiteralPath $FolderPath) {
            [array]$ValidPath += $FolderPath
        }
    }
    # get all items in valid folderpath
    if ($ValidPath) {
        foreach ($Item in $ValidPath) {
            if (Test-Path -LiteralPath $Item){
                $LogFiles += Get-ChildItem -Recurse -LiteralPath $Item -Filter '*.log'
            }
        }
    }
    else {
        Write-Output -InputObject 'No logs found!'
        break
    }

    #Filter logs for given date
    if (!($Localpath)) {
        if (($StartDate.ToString().Length -gt 6) -or ($EndDate.ToString().Length -gt 6)) {
            if (($StartDate.ToString().Length -gt 6) -and ($EndDate.ToString().Length -gt 6)) {
                $LogFiles = $LogFiles | Where-Object{$_.name.substring(($_.name.length -14),8) -ge $StartDate -and $_.name.substring(($_.name.length -14),8) -le $EndDate}
            }
            elseif (($StartDate.ToString().Length -gt 6) -and ($EndDate.ToString().Length -eq 6)) {
                $LogFiles = $LogFiles | Where-Object{$_.name.substring(($_.name.length -14),8) -ge $StartDate -and $_.name.substring(($_.name.length -14),6) -le $EndDate}
            }
            else {
                $LogFiles = $LogFiles | Where-Object{$_.name.substring(($_.name.length -14),6) -ge $StartDate -and $_.name.substring(($_.name.length -14),8) -le $EndDate}
            }
        }
        else {
            $LogFiles = $LogFiles | Where-Object{$_.name.substring(($_.name.length -14),6) -ge $startdate -and $_.name.substring(($_.name.length -14),6) -le $enddate}
        }
        $MAPIServer = "EXTRACT_PREFIX(EXTRACT_TOKEN(EXTRACT_PATH(filename),1,'\\\\'),0,'\\')"
    }
    else {
        $LogFiles | ForEach-Object -Process {$LogsFrom += "'" + $_.FullName + "',"}
        $MAPIServer = 'server-ip'
    }

}

Process{
    if ($LogFiles) {
        $LogFiles | foreach-Object{$Logsfrom += "'" + $_.fullname +"',"}
        $Logsfrom = $Logsfrom.TrimEnd(',')
        Write-Output -InputObject 'Logs to be parsed:'
        $LogFiles |Select-Object -ExpandProperty fullname | Sort-Object -Property fullname
    }
    else {
        Write-Output -InputObject 'No logs found!'
        break
    }

    # check for header from logs
    if ($E16CU4orLater) {
        Write-Host "Get headers from file" ($logsfrom.Split(",") | select -First 1 ).Replace("'","")
        [string]$fields = Get-Content ($logsfrom.Split(",") | select -First 1 ).Replace("'","") -TotalCount 1
        $fields = $fields.Replace("DateTime","Day,Time,Server")
    }
    else {
        Write-Host "Get headers from file" ($logsfrom.Split(",") | select -First 1 ).Replace("'","")
        [string]$fields = Get-Content ($logsfrom.Split(",") | select -First 1 ).Replace("'","") -TotalCount 5 | select -Last 1
        $fields = $fields.Replace("#Fields: date-time","Day,Time").Replace("client-name","Server,Mailbox,AvgClientLatency,AvgCasRPCProcessingTime,AvgMbxProcessingTime,MaxCasRPCProcessingTime,ClientRPCCount,ServerRPCCount,client-name")
    }

    # set stamps
    if ($userid -OR $userids) {
        if ($UserID){
            $stamp = $UserID + '_' + ($ADSite -join '_') + '_' + $(Get-Date -Format HH-mm-ss)
        }
        elseif ($UserIDs){
            $string = buildstamp -strings $UserIDs
            if ($string.Length -gt 30) {
                $stamp = 'multiple_users_' + ($ADSite -join '_') + '_' + $(Get-Date -Format HH-mm-ss)
            }
            else {
                $stamp = $string + ($ADSite -join '_') + '_' + $(Get-Date -Format HH-mm-ss)
            }
        }
    }
    else {
        $stamp = ($ADSite -join '_') + '_' + $(Get-Date -Format HH-mm-ss)
    }

    #build query
    if ($E16CU4orLater) {
        $MAPIServer = "EXTRACT_PREFIX(EXTRACT_TOKEN(EXTRACT_PATH(filename),1,'\\\\'),0,'\\')"
        if ($ErrorReport) {
            $stamp = ($ADSite -join "_") + "_ErrorReport_" + $(Get-Date -Format HH-mm-ss)
            $query_MAPI = @"
Select $fields

USING
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: DateTime],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: DateTime],0,'T')),0,'.'), 'hh:mm:ss') AS Time,
$MAPIServer AS Server

INTO $outpath\*_ErrorReport_MAPI_$stamp.csv
From

"@

            $query_MAPI += $Logsfrom
            $query_MAPI += @"

WHERE GenericErrors IS NOT NULL AND Time IS NOT NULL
GROUP BY $fields
ORDER BY Day,Time
"@
   
        }
        else {
            $query_MAPI = @"
Select $fields

USING
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: datetime],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: datetime],0,'T')),0,'.'), 'hh:mm:ss') AS Time,
$MAPIServer AS Server

INTO $outpath\*_MAPI_$stamp.csv
From

"@

            $query_MAPI += $Logsfrom

            if ($UserID){
                Write-Host -fore yellow "Query for user $UserID!"
                $query_MAPI += @"
    WHERE (AuthenticatedUserEmail LIKE '%$UserID%') OR (ActAsUserEmail LIKE '%$UserID%')

"@
            }

            if ($UserIDs){
                [string]$QueryString= ""
                foreach ($UserID in $UserIDs) {
                    $QueryString += "((AuthenticatedUserEmail LIKE '%$UserID%') OR (ActAsUserEmail LIKE '%$UserIDs%')) OR " 
                }

                #build string from multiple addresses
                $QueryString = $QueryString.Substring("0",($QueryString.LastIndexOf(")")+1))
                Write-Host -fore yellow "Query for users $([string]::Join(";",$UserIDs))!"
                $query_MAPI += @"

WHERE $QueryString
"@
            }

            $query_MAPI += @"
GROUP BY $fields
ORDER BY Day,Time 
"@

        }
        # workaround for limitation of path length, therefore we put the query into a file
        Set-Content -Value $query_MAPI $Outpath\query.txt -Force

        Write-Output "Start query!"
        & $Logparser file:$Outpath\query.txt -i:csv -nSkipLines:5 -e:100 -iw:on -dtLines:0

    }
    else {
        if ($ErrorReport) {

            $stamp = ($ADSite -join '_') + '_ErrorReport_' + $(Get-Date -Format HH-mm-ss)

            $query_MAPI = @"
Select $fields

USING
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: date-time],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: date-time],0,'T')),0,'.'), 'hh:mm:ss') AS Time,
SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3) AS Mailbox,
TO_LOWERCASE(SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3)) AS Mailbox2,
TO_LOWERCASE(REPLACE_STR(EXTRACT_SUFFIX(protocol,0,'\\'),']','')) AS Mailbox3,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'ClientRPCCount'),0,';'),'=','') AS ClientRPCCount,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'ServerRPCCount'),0,';'),'=','') AS ServerRPCCount,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'AvgClientLatency'),0,';'),'=','') AS AvgClientLatency,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'AvgCasRPCProcessingTime'),0,';'),'=','') AS AvgCasRPCProcessingTime,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'AvgMbxProcessingTime'),0,';'),'=','') AS AvgMbxProcessingTime,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'MaxCasRPCProcessingTime'),0,';'),'=','') AS MaxCasRPCProcessingTime,
$MAPIServer AS Server

INTO    $outpath\*_MAPI_$stamp.csv
From

"@

            $query_MAPI += $Logsfrom
            $query_MAPI += @"

WHERE failures IS NOT NULL AND Time IS NOT NULL
GROUP BY $fields
ORDER BY Day,Time
"@

        }
        elseif ($ConcurrentConnections) {
            $stamp = ($ADSite -join '_') + '_Concurrent_' + $(Get-Date -Format HH-mm-ss)
            $query_MAPI = @"
Select Day,Time,Session,Mailbox

USING
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: date-time],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
QUANTIZE(TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: date-time],0,'T')),0,'.'), 'hh:mm:ss'), $ConcurrentIntervall) AS Time,
SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3) AS Mailbox,
TO_LOWERCASE(REPLACE_STR(EXTRACT_SUFFIX(protocol,0,'\\'),']','')) AS Mailbox3,
session-id AS Session,
$MAPIServer AS Server

From
"@
            $query_MAPI += $Logsfrom
            if ($UserID){
                $query_MAPI += @"

  WHERE ((Mailbox LIKE '%$UserID%') OR (Mailbox3 LIKE '%$UserID%')) AND
"@
            }
            elseif ($UserIDs){
                [string]$QueryString= ''
                foreach ($UserID in $UserIDs) {
                    $QueryString += "((Mailbox LIKE '%$UserID%') OR (Mailbox3 LIKE '%$UserID%')) OR"
                }
                $QueryString = $QueryString.Substring('0',($QueryString.LastIndexOf(')')+1))
                $query_MAPI += @"

  WHERE ($QueryString)  AND
"@    
            }
            else{
                $query_MAPI += @'

  WHERE 
'@
            }
            $query_MAPI += @"
 ((session-id IS NOT NULL) AND (Mailbox NOT LIKE '%HealthMailbox') AND (TIME IS NOT NULL))
GROUP BY Day,Time,Mailbox,Session
ORDER BY Time ASC
"@

            # workaround for limitation of path length, therefore we put the query into a file
            Set-Content -Value $query_MAPI -Path $Outpath\query.txt -Force
            Write-Output -InputObject 'Start Concurrent query!'
            & $Logparser file:$Outpath\query.txt -i:csv -nSkipLines:4 -e:100 -iw:on -dtLines:0 -o:csv -q:on | & $Logparser "SELECT Day,Time,Mailbox,COUNT(Mailbox) AS SessionCount INTO $outpath\*_MAPI_$stamp.csv FROM STDIN GROUP BY DAY,TIME,Mailbox" -i:csv -e:100 -iw:on
            Write-Output -InputObject 'Query done!'
            # clean query file
            Get-ChildItem -LiteralPath $Outpath -Filter query.txt | Remove-Item -Confirm:$false | Out-Null
            break
        }
        elseif ($ClientReport){
            $stamp = ($ADSite -join '_') + '_ClientReport_' + $(Get-Date -Format HH-mm-ss)
            $query_MAPI = @"
Select DISTINCT Day,Client,Version,Count(*) AS TotalHits
USING
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: date-time],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
TO_LOWERCASE(client-software) AS Client,
TO_LOWERCASE(client-software-version) AS Version

INTO    $outpath\*_MAPI_$stamp.csv
From

"@
            $query_MAPI += $Logsfrom
            $query_MAPI += @'

WHERE client-software IS NOT NULL AND Day IS NOT NULL
GROUP BY Day,Client,Version
ORDER BY TotalHits DESC
'@

        }
        else {
            $query_MAPI = @"
Select $fields

USING
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: date-time],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: date-time],0,'T')),0,'.'), 'hh:mm:ss') AS Time,
SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3) AS Mailbox,
TO_LOWERCASE(SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3)) AS Mailbox2,
TO_LOWERCASE(REPLACE_STR(EXTRACT_SUFFIX(protocol,0,'\\'),']','')) AS Mailbox3,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'ClientRPCCount'),0,';'),'=','') AS ClientRPCCount,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'ServerRPCCount'),0,';'),'=','') AS ServerRPCCount,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'AvgClientLatency'),0,';'),'=','') AS AvgClientLatency,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'AvgCasRPCProcessingTime'),0,';'),'=','') AS AvgCasRPCProcessingTime,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'AvgMbxProcessingTime'),0,';'),'=','') AS AvgMbxProcessingTime,
REPLACE_CHR(EXTRACT_PREFIX(EXTRACT_SUFFIX(performance-data,0,'MaxCasRPCProcessingTime'),0,';'),'=','') AS MaxCasRPCProcessingTime,
$MAPIServer AS Server

INTO    $outpath\*_MAPI_$stamp.csv
From

"@
            $query_MAPI += $Logsfrom
            if ($UserID){
                Write-Host -fore yellow "Query for user $UserID!"
                $query_MAPI += @"

    WHERE (Mailbox LIKE '%$UserID%') OR (Mailbox3 LIKE '%$UserID%')
"@
            }

            elseif ($UserIDs){
                [string]$QueryString= ''
                foreach ($UserID in $UserIDs) {
                    $QueryString += "((Mailbox LIKE '%$UserID%') OR (Mailbox3 LIKE '%$UserIDs%')) OR " 
                }
                #build string from multiple addresses
                $QueryString = $QueryString.Substring('0',($QueryString.LastIndexOf(')')+1))
                Write-Host -fore yellow "Query for users $([string]::Join(';',$UserIDs))!"
                $query_MAPI += @"

WHERE $QueryString
"@
            }
            else{
                $query_MAPI += @'
    WHERE Day IS NOT NULL
'@
            }

            $query_MAPI += @"

GROUP BY $fields
ORDER BY Day,Time 
"@
        }
        # workaround for limitation of path length, therefore we put the query into a file
        Set-Content -Value $query_MAPI -Path $Outpath\query.txt -Force
        Write-Output -InputObject 'Start query!'
        & $Logparser file:$Outpath\query.txt -i:csv -nSkipLines:4 -e:100 -iw:on -dtLines:0
        Write-Output -InputObject 'Query done!'
    }
}
End{
    # clean query file
    Get-ChildItem -LiteralPath $Outpath -Filter query.txt | Remove-Item -Confirm:$false | Out-Null
}