using module ./NetUtils.psm1   # must be before any executable code

#requires -version 7

param (
    [Parameter(Mandatory = $true)][string]$mac,
    [Parameter(Mandatory = $false)][string]$subnet,
    [Parameter(Mandatory = $false)][bool]$throttleForWifi = $false
)


class FindIpByMAC {

    static [void] ThrowIfAnythingLooksDangerous([System.Net.NetworkInformation.PhysicalAddress]$mac, [Subnet]$subnet) {

        [System.Net.IPAddress]$probableGatewayIp = $subnet.GetFirstValidHostIp()
        if (-not [NetUtils]::IsIpUp($probableGatewayIp)) {
            [NetUtils]::ComplainAndThrow("Probable gateway '$probableGatewayIp' didn't respond to ping. Since this script risks angering your IT dept if misused, we're stopping now as a precaution.")
        }
    }

    static [string] Do([string]$macStr, [string]$subnetStr, [bool]$throttleForWifi) {

        [System.Net.NetworkInformation.PhysicalAddress]$mac = [System.Net.NetworkInformation.PhysicalAddress]::Parse($macStr)

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

        Write-Host ("Scanning subnet " + $subnet.ToCIDR() + " for MAC address " + $mac.ToString() + "...")

        #We do a loop instead of a range, in case the range is big enough that we want to avoid
        # instantiating it as an array in memory.
        [System.Net.IPAddress]$foundIp = [NetUtils]::GetIpOfMac($subnet, $mac, $throttleForWifi)

        if ($null -eq $foundIp) {
            Write-Host ("`Network on subnet " + $subnet.ToCIDR() + " did not respond with any IP address after ARP request for MAC address " + $mac.ToString() + ".")
            exit 1;
        }
        
        return $foundIp
    }

}

if (-not $PSBoundParameters.ContainsKey('throttleForWifi')) {
    Write-Host "Using heavy parallelism. pass `-throttleForWifi `$true if this causes your WiFi to disconnect"
}

[FindIpByMAC]::Do($mac, $subnet, $throttleForWifi)

