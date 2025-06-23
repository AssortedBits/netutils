#requires -version 7

using module "./NetUtils.psm1"

param (
    [Parameter(Mandatory = $true)][string]$mac,
    [Parameter(Mandatory = $false)][string]$subnet,
    [Parameter(Mandatory = $false)][bool]$throttleForWifi = $false
)


class FindIpByMAC {

    static [void] ThrowIfAnythingLooksDangerous([string]$mac, [Subnet]$subnet) {

        [System.Net.IPAddress]$probableGatewayIp = $subnet.GetFirstValidHostIp()
        if (-not [NetUtils]::IsIpUp($probableGatewayIp)) {
            [NetUtils]::ComplainAndThrow("Probable gateway '$probableGatewayIp' didn't respond to ping. Since this script risks angering your IT dept if misused, we're stopping now as a precaution.")
        }
    }

    static [string] Do([string]$mac, [string]$subnetStr, [bool]$throttleForWifi) {

        [Subnet]$subnet = $null

        if ( $null -ne $subnetStr -and $subnetStr.Length -gt 0) {
            $subnet = [Subnet]::FromCIDR($subnetStr)
        }
        else {
            Write-Host -NoNewline "No subnet supplied. Deducing..."
            [Subnet[]]$subnets = [Subnet]::Current()
            if ($subnets.Count -eq 0) {
                [NetUtils]::ComplainAndThrow("no subnet supplied, and failed to deduce one automatically")
            }
            $subnet = $subnets[0]

            Write-Host (" " + $subnet.ToCIDR() + "`nIf this is the wrong network adapter, then rerun and specify the subnet explicitly.")
        }

        [FindIpByMAC]::ThrowIfAnythingLooksDangerous($mac, $subnet)

        [uint]$nParallel = $throttleForWifi ? 8 : 127

        $modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'NetUtils.psm1'
        $moduleCode = Get-Content -Path $modulePath -Raw

        Write-Host ("Scanning subnet " + $subnet.ToCIDR() + " for MAC address $mac ...")

        #We do a loop instead of a range, in case the range is big enough that we want to avoid
        # instantiating it as an array in memory.
        [string[]]$foundArr = & {

            [System.Net.IPAddress]$lowIp = $subnet.GetFirstValidHostIp()
            [System.Net.IPAddress]$highIp = $subnet.GetLastValidHostIp()

            [UInt32]$lowIpInt = [NetUtils]::ToInt($lowIp)
            [UInt32]$highIpInt = [NetUtils]::ToInt($highIp)

            for ([UInt32]$ipInt = $lowIpInt; $ipInt -le $highIpInt; $ipInt++) {
                [System.Net.IPAddress]$ip = [NetUtils]::ToIp($ipInt)
                Write-Output $ip
            }
        } |
        ForEach-Object -Parallel {

            [System.Net.IPAddress]$ip = $_
            [Subnet]$subnet = $using:subnet
            [string]$mac = $using:mac

            #Because of some devilish mysterious behavior on my machine,
            # Import-Module will not work (fails silently), in any context,
            # even with a minimal boilerplate example, no matter how many
            # Copilot instructions I follow.
            #Import-Module $using:modulePath
            Invoke-Expression $using:moduleCode

            if ([NetUtils]::IpHasMAC($ip, $mac)) {
                Write-Output "Found $mac at: $ip"
            }
        } -ThrottleLimit $nParallel |
        Select-Object -First 1       

        if ($foundArr.Count -lt 1) {
            Write-Host ("`No network device on subnet " + $subnet.ToCIDR() + " with MAC address $mac responded to pings within one second.")
            exit 1;
        }
        
        return $foundArr[0]
    }

}

if (-not $PSBoundParameters.ContainsKey('throttleForWifi')) {
    Write-Host "Using heavy parallelism. pass `-throttleForWifi `$true if this causes your WiFi to disconnect"
}

[FindIpByMAC]::Do($mac, $subnet, $throttleForWifi)

