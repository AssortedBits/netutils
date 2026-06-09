using module ./ArpTools.psm1
using module ./Misc.psm1
using module ./Subnet.psm1

#requires -version 7


class NetTools {

    #Running this function, if it returns true, has the side-effect of
    # caching that device's MAC in a lookup table maintained by our OS.
    static [bool] Ping([System.Net.IPAddress]$ip) {
        [bool]$result = Test-Connection -Quiet -ComputerName $ip.ToString() -Count 1 -TimeoutSeconds 1
        return $result
    }

    static [string[]] GetTableEntryForIp([System.Net.IPAddress]$ip) {
        [string[]]$output = arp -a $ip.ToString()
        return $output
    }

    static [System.Net.NetworkInformation.PhysicalAddress] GetMacOfIp(
        [System.Net.IPAddress]$ip
    ) {
        return [ArpToolsWrapper]::GetMacOfIp($ip)
    }

    static [System.Net.IPAddress] GetIpOfMac(
        [Subnet]$subnet,
        [System.Net.NetworkInformation.PhysicalAddress]$mac,
        [bool]$throttleForWifi = $false
    ) {
        return [ArpToolsWrapper]::GetIpOfMac($subnet, $mac, $throttleForWifi)
    }

}
