using module ./Subnet.psm1

#requires -version 7

$csPath = Join-Path $PSScriptRoot 'ArpTools.cs'

if (-not [System.IO.File]::Exists($csPath)) {
    throw "C# source file not found: $csPath"
}

# Only add the type once per session
if (-not ('ArpTools' -as [type])) {
    Add-Type -Path $csPath
}


#Due to the order in which PowerShell does compilation vs execution,
# the type that ArpTools module exports at run-time cannot be directly
# used in class member functions, even in clients. Instead, we need to
# wrap invocations in non-class-member functions.

function Find-IpByMac {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.IPAddress] $StartIp,

        [Parameter(Mandatory)]
        [System.Net.IPAddress] $EndIp,

        [Parameter(Mandatory)]
        [System.Net.NetworkInformation.PhysicalAddress] $Mac,

        [Parameter()]
        [bool] $ThrottleForWifi = $false
    )

    [int] $maxConcurrency = 16
    [TimeSpan] $interProbeDelay = [TimeSpan]::FromMilliseconds(10)
    if ($ThrottleForWifi) {
        $maxConcurrency = 2
        $interProbeDelay = [TimeSpan]::FromMilliseconds(50)
    }

    # Get a CancellationToken that flips when Ctrl-C is pressed
    [System.Threading.CancellationToken]$token = $PSCmdlet.PipelineStopToken

    $task = [ArpTools]::FindByMacAsync(
        $StartIp, $EndIp, $Mac, $maxConcurrency, $interProbeDelay, $token)

    $task.GetAwaiter().GetResult()
}

function Get-MacByIp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.IPAddress] $Ip
    )

    return [System.Net.NetworkInformation.PhysicalAddress](
        [ArpTools]::TrySendArp($Ip))
}


class ArpToolsWrapper {

    static [System.Net.IPAddress] GetIpOfMac(
        [Subnet]$subnet,
        [System.Net.NetworkInformation.PhysicalAddress]$mac,
        [bool]$throttleForWifi = $false
    ) {
        return [System.Net.IPAddress](
            Find-IpByMac `
                -StartIp $subnet.GetFirstValidHostIp() `
                -EndIp $subnet.GetLastValidHostIp() `
                -Mac $mac `
                -ThrottleForWifi $throttleForWifi)
    }

    static [System.Net.NetworkInformation.PhysicalAddress] GetMacOfIp(
        [System.Net.IPAddress]$ip
    ) {
        return [System.Net.NetworkInformation.PhysicalAddress](
            Get-MacByIp `
                -Ip $ip)
    }

}
