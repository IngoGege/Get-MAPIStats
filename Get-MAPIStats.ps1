<#
        .SYNOPSIS

        Created by: https://ingogegenwarth.wordpress.com/
        Version:    42 ("What do you get if you multiply six by nine?")
        Changed:    03.03.2022

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

        .PARAMETER ErrorReport

        Creates a report of all errors.

        .PARAMETER Localpath

        if you have already collected log files, you can define the path to those in order to have them analyzed

        .EXAMPLE

        .\Get-MAPIStats.ps1 -UserID Ingo -Outpath $env:USERPROFILE\Documents

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
    [System.String]
    $UserID,

    [parameter( ParameterSetName='ALL')]
    [parameter( ParameterSetName='USERS')]
    [parameter(Mandatory=$false, Position=1)]
    [System.Array]
    $UserIDs,

    [parameter( Mandatory=$false, Position=2)]
    [System.Int32]
    $StartDate="$((get-date).ToString('yyMMdd'))",

    [parameter( Mandatory=$false, Position=3)]
    [System.Int32]
    $EndDate="$((get-date).ToString('yyMMdd'))",

    [parameter( Mandatory=$false, Position=4)]
    [ValidateScript({if (Test-Path -Path $_ -PathType leaf) {$True} else {Throw 'Logparser could not be found!'}})]
    [System.String]
    $Logparser="${env:ProgramFiles(x86)}\Log Parser 2.2\LogParser.exe",

    [parameter( Mandatory=$false, Position=5)]
    [System.String[]]
    $ADSite="([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name",

    [parameter( Mandatory=$false, Position=6)]
    [ValidateScript({if (Test-Path -Path $_ -PathType container) {$True} else {Throw ('{0} is not a valid path!' -f $_)}})]
    [System.String]
    $Outpath = $env:temp,

    [parameter( ParameterSetName='ErrorReport')]
    [parameter( Mandatory=$false, Position=7)]
    [System.Management.Automation.SwitchParameter]
    $ErrorReport,

    [parameter( Mandatory=$false, Position=8)]
    [System.Array]
    $SpecifiedServers,

    [parameter( Mandatory=$false, Position=9)]
    [ValidateScript({if (Test-Path -Path $_ -PathType container) {$True} else {Throw "$_ is not a valid path!"}})]
    [System.String]
    $Localpath
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
            $valid = @('2','4','16','20','32','36','38','54','64','16385','16439','16423')
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

    $LogFolder = '\Logging\MapiHttp\Mailbox'

    # set variables
    [string]$FolderPath = $null
    [array]$LogFiles = $null
    [array]$TempLogs = $null
    [string]$LogsFrom = $null

    #Get Server and folders
    if (!($Localpath)) {
        # get CAS servers
        [array]$Servers += GetExchServer -Role 16385,16439,16423 -ADSites $ADSite | Where-Object {$_.Properties.versionnumber -ge '1942061725'}

        if ($SpecifiedServers) {
            $Servers = $Servers | Where-Object {$SpecifiedServers -contains $_.Properties.name}
        }
        if ($Servers) {
            Write-Output -InputObject 'Found the following Exchange servers:', $($Servers | foreach-Object{$_.Properties.name})
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
    Write-Host "Get headers from file" ($logsfrom.Split(",") | select -First 1 ).Replace("'","")
    [string]$fields = Get-Content ($logsfrom.Split(",") | select -First 1 ).Replace("'","") -TotalCount 1
    $fields = $fields.Replace("DateTime","Day,Time,Server")

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
TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: datetime],0,'T')),0,'.'), 'hh:mm:ss') AS Time ,
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
End{
    # clean query file
    Get-ChildItem -LiteralPath $Outpath -Filter query.txt | Remove-Item -Confirm:$false | Out-Null
}