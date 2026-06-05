using module ./NetUtils.psm1   # must be before any executable code

#requires -version 7

param (
    [Parameter(Mandatory = $true)][string]$mac,
    [Parameter(Mandatory = $false)][string]$subnet
)


class FindIpByMAC {

    static [void] ThrowIfAnythingLooksDangerous([System.Net.NetworkInformation.PhysicalAddress]$mac, [Subnet]$subnet) {

        [System.Net.IPAddress]$probableGatewayIp = $subnet.GetFirstValidHostIp()
        if (-not [NetUtils]::IsIpUp($probableGatewayIp)) {
            [NetUtils]::ComplainAndThrow("Probable gateway '$probableGatewayIp' didn't respond to ping. Since this script risks angering your IT dept if misused, we're stopping now as a precaution.")
        }
    }

    static [string] Do([string]$macStr, [string]$subnetStr) {

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

        [int]$logBatchSize = 10

        [bool]$done = $false

        #We do a loop instead of a range, in case the range is big enough that we want to avoid
        # instantiating it as an array in memory.
        [System.Net.IPAddress]$foundIp = & {
            [System.Net.IPAddress]$lowIp = $subnet.GetFirstValidHostIp()
            [System.Net.IPAddress]$highIp = $subnet.GetLastValidHostIp()

            [UInt32]$lowIpInt = [NetUtils]::ToInt($lowIp)
            [UInt32]$highIpInt = [NetUtils]::ToInt($highIp)

            for ([UInt32]$ipInt = $lowIpInt; $ipInt -le $highIpInt; $ipInt++) {
                [System.Net.IPAddress]$ip = [NetUtils]::ToIp($ipInt)
                Write-Output $ip

                if (($ipInt - $lowIpInt) % $logBatchSize -eq 0) {
                    Write-Host ("progress: " + $ip.ToString() + "...")
                }
            }
        } |
        ForEach-Object {

            [System.Net.IPAddress]$ip = $_

            #Skip remaining iters after success.
            if ($done) {
                return
            }

            [System.Net.NetworkInformation.PhysicalAddress]$foundMac = [NetUtils]::GetMac($ip)
            if ($null -ne $foundMac -and $foundMac.ToString() -eq $mac.ToString()) {
                return $ip
            }
        } |
        #Causes PowerShell to cancel iterations that haven't started yet.
        Select-Object -First 1       

        if ($null -eq $foundIp) {
            Write-Host ("`Network on subnet " + $subnet.ToCIDR() + " did not respond with any IP address after ARP request for MAC address " + $mac.ToString() + ".")
            exit 1;
        }
        
        return $foundIp
    }

}

[FindIpByMAC]::Do($mac, $subnet)

