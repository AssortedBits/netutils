#requires -version 7

using module "./NetUtils.psm1"

param (
    [Parameter(Mandatory = $true)][string]$mac,
    [Parameter(Mandatory = $true)][string]$networkAddress,
    [Parameter(Mandatory = $true)][string]$netmask
)


class FindIpByMAC {

    static [void] ThrowIfInvalidParams([string]$mac, [System.Net.IPAddress]$networkIp, [System.Net.IPAddress]$netmask) {

        if ("" -eq $mac) {
            [NetUtils]::ComplainAndThrow("no MAC address supplied")
        }

        if ($null -eq $networkIp) {
            [NetUtils]::ComplainAndThrow("no network IP address supplied")
        }

        if ($null -eq $netmask) {
            [NetUtils]::ComplainAndThrow("no netmask supplied")
        }

        [NetUtils]::ThrowIfNotV4($networkIp)
        [NetUtils]::ThrowIfNotV4($netmask)
        [NetUtils]::ThrowIfNetworkAddressAndNetmaskDisagree($networkIp, $netmask)
    }

    static [void] ThrowIfAnythingElseLooksDangerous([string]$mac, [System.Net.IPAddress]$networkIp, [System.Net.IPAddress]$netmask) {

        [System.Net.IPAddress]$probableGatewayIp = [NetUtils]::GetFirstValidHostIp($networkIp)
        if (-not [NetUtils]::IsIpUp($probableGatewayIp)) {
            [NetUtils]::ComplainAndThrow("Probable gateway '$probableGatewayIp' didn't respond to ping. Since this script risks angering your IT dept if misused, we're stopping now as a precaution.")
        }
    }

    static [string] Do([string]$mac, [System.Net.IPAddress]$networkIp, [System.Net.IPAddress]$netmask) {

        [FindIpByMAC]::ThrowIfInvalidParams($mac, $networkIp, $netmask)

        [FindIpByMAC]::ThrowIfAnythingElseLooksDangerous($mac, $networkIp, $netmask)

        $modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'NetUtils.psm1'
        $moduleCode = Get-Content -Path $modulePath -Raw

        #We do a loop instead of a range, in case the range is big enough that we want to avoid
        # instantiating it as an array in memory.
        [string[]]$foundArr = & {

            [System.Net.IPAddress]$lowIp = [NetUtils]::GetFirstValidHostIp($networkIp)
            [System.Net.IPAddress]$highIp = [NetUtils]::GetLastValidHostIp($networkIp, $netmask)

            [UInt32]$lowIpInt = [NetUtils]::ToInt($lowIp)
            [UInt32]$highIpInt = [NetUtils]::ToInt($highIp)

            for ([UInt32]$ipInt = $lowIpInt; $ipInt -le $highIpInt; $ipInt++) {
                [System.Net.IPAddress]$ip = [NetUtils]::ToIp($ipInt)
                Write-Output $ip
            }
        } |
        ForEach-Object -Parallel {

            [System.Net.IPAddress]$ip = $_

            #Because of some devilish mysterious behavior on my machine,
            # Import-Module will not work (fails silently), in any context,
            # even with a minimal boilerplate example, no matter how many
            # Copilot instructions I follow.
            #Import-Module $using:modulePath
            Invoke-Expression $using:moduleCode

            if ([NetUtils]::IpHasMAC($ip, $using:mac)) {
                Write-Output $ip
            }
        } -ThrottleLimit 20 |
        Select-Object -First 1       

        if ($foundArr.Count -lt 1) {
            Write-Host "no network device in the given IP range with given MAC responded to pings within one second"
            exit 1;
        }
        
        return $foundArr[0]
    }

}

[FindIpByMAC]::Do($mac, [System.Net.IPAddress]::Parse($networkAddress), [System.Net.IPAddress]::Parse($netmask))

