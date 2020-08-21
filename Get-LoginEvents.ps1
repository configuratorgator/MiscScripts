<#

.SYNOPSIS
Author: Brian Gade (@Configur8rGator, www.configuratorgator.com)

.DESCRIPTION
Provides a function that gets logon events from the event log and provides
a way to filter and parse the data.  You can run this as a script or copy
and paste the data into a function that's used elsewhere.

.PARAMETER DataSourceComputerName
String, Optional. The name of the computer on which to search the event log.

.PARAMETER StartTime
DateTime, Optional. The earliest allowable timestamp in the event log.

.PARAMETER EndTime
DateTime, Optional. The latest allowable timestamp in the event log.

.PARAMETER ExcludeComputerAccounts
Switch, Optional. Excludes computer accounts and 'NT AUTHORITY\SYSTEM' accounts from the results.

.PARAMETER TargetUsername
String, Optional, Implies ExcludeComputerAccounts. Limits the results to events associated with a specific username.

.EXAMPLE
All non-system logins in the last 24 hours from domain controller DC01.contoso.com
$Logons = .\Get-LoginEvents.ps1 -DataSourceComputerName DC01.contoso.com -StartTime ((Get-Date).AddDays(-1)) -ExcludeComputerAccounts

All logins on the local computer for username jdoe and show verbose output
$Logons = .\Get-LoginEvents.ps1 -TargetUsername jdoe -Verbose

.NOTES
Change log:
v1.0.0, ConfiguratorGator, 08/20/2020 - Original Version

.LINK
The core of this code comes from ThePoSHWolf and 99% of credit for this should go there.  I just made some tweaks
like adding support for filtering out computer accounts and searching for a specific username.
https://theposhwolf.com/howtos/Get-LoginEvents/?fbclid=IwAR3HkPNZ2M3Ujrvjr0ryu5uaCBtgmsf4pDVRlerRz-XUxfFp8NTkrCTqgYA

#>
# DEFINE PARAMETERS ----------------------------------------------
    # Define parameters
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][Alias('Name')]
            [string] $DataSourceComputerName = $ENV:ComputerName,
        [Parameter(Mandatory=$False)]
            [datetime] $StartTime,
        [Parameter(Mandatory=$False)]
            [datetime] $EndTime = (Get-Date),
        [Parameter(Mandatory=$False)]
            [switch] $ExcludeComputerAccounts,
        [Parameter(Mandatory=$False)]
            [string] $TargetUsername
    )
# END DEFINE PARAMETERS ------------------------------------------
# DEFINE VARIABLES -----------------------------------------------

$ExcludedComputerAccounts = "DWM-1","LOCAL SERVICE","NETWORK SERVICE","SYSTEM"
$filterHt = @{LogName = 'Security';ID = 4624}
$Results = @()

# END DEFINE VARIABLES -------------------------------------------
# SCRIPT BODY ----------------------------------------------------

# If a Start Time was specified, add StartTime to the event filter hashtable
If($PSBoundParameters.ContainsKey('StartTime'))
{
    $filterHt['StartTime'] = $StartTime
    Write-Verbose "Added the start time to the event filter"
}

# If an End Time was specified, add EndTime to the event filter hashtable
If($PSBoundParameters.ContainsKey('EndTime'))
{
    $filterHt['EndTime'] = $EndTime
    Write-Verbose "Added the end time to the event filter"
}

# Get the events
Write-Verbose "Querying the event log.  This may take a while..."
$LogonEvents = Get-WinEvent -ComputerName $DataSourceComputerName -FilterHashtable $filterHt
Write-Verbose "Found $($LogonEvents.Count) results"

# If the user is looking for a specific username, find those results
# ElseIf the user chose to exclude computer accounts, remove them from the results
If($PSBoundParameters.ContainsKey('TargetUsername'))
{
    Write-Verbose "Filtering the events based on user $TargetUsername..."
    $LogonEvents = $LogonEvents | Where-Object{$_.Properties.Value[5] -eq $TargetUsername}
    Write-Verbose "$($LogonEvents.Count) events remain after filtering"
}
ElseIf($ExcludeComputerAccounts -eq $True)
{
    Write-Verbose "Removing computer and SYSTEM accounts from the results..."
    $LogonEvents = $LogonEvents | Where-Object{$_.Properties.Value[5] -NotLike '*$*' -and $_.Properties.Value[5] -NotIn $ExcludedComputerAccounts}
    Write-Verbose "$($LogonEvents.Count) events remain after filtering"
}

# Loop through the events to provide output
Write-Verbose "Converting the data to a friendly format..."
ForEach($Event in $LogonEvents)
{
    $Results += [pscustomobject]@{
        DataSourceComputerName = $DataSourceComputerName
        TimeStamp = $Event.TimeCreated
        UserDomain = $Event.Properties.Value[6]
        Username = $Event.Properties.Value[5]
        LogonType = Switch($Event.Properties.Value[8])
                    {
                        2 {"Interactive"}
                        3 {"Network"}
                        4 {"Batch"}
                        5 {"Service"}
                        7 {"Unlock"}
                        8 {"NetworkClearText"}
                        9 {"NewCredentials"}
                        10 {"RemoteInteractive"}
                        11 {"CachedInteractive"}
                    }
        ComputerIPAddress = $Event.Properties.Value[18]
        ComputerName = $Event.Properties.Value[11]
        }
}

# Return the results
Write-Verbose "Finished!"
Return $Results

# END SCRIPT BODY ------------------------------------------------
# END SCRIPT -----------------------------------------------------
# SIGNATURE ------------------------------------------------------
