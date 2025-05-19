#requires -version 7

class NetUtils {

    static [void] ComplainAndThrow([string]$errStr) {
        Write-Host $errStr
        throw $errStr
    }

    static [UInt32] ToInt([System.Net.IPAddress]$ip) {
        [byte[]]$byteArr = $ip.GetAddressBytes()
        [Array]::Reverse($byteArr)
        return [BitConverter]::ToUInt32($byteArr, 0)
    }

    static [System.Net.IPAddress] ToIp([UInt32]$int) {
        [byte[]]$byteArr = [BitConverter]::GetBytes($int)
        [Array]::Reverse($byteArr)
        return [System.Net.IPAddress]::new($byteArr)
    }

    static [System.Net.IPAddress] PlusOne([System.Net.IPAddress]$ip) {

        return [NetUtils]::ToIp([NetUtils]::ToInt($ip) + 1)
    }

    static [System.Net.IPAddress] MinusOne([System.Net.IPAddress]$ip) {

        return [NetUtils]::ToIp([NetUtils]::ToInt($ip) - 1)
    }

    static [bool] LessOrEqual([System.Net.IPAddress]$lhs, [System.Net.IPAddress]$rhs) {
        return [NetUtils]::ToInt($lhs) -le [NetUtils]::ToInt($rhs)
    }

    #Running this function, if it returns true, has the side-effect of
    # caching that device's MAC in a lookup table maintained by our OS.
    static [bool] IsIpUp([System.Net.IPAddress]$ip) {
        [bool]$result = Test-Connection -Quiet -ComputerName $ip.ToString() -Count 1 -TimeoutSeconds 1
        return $result
    }

    static [bool] AddToMACLookupTable([System.Net.IPAddress]$ip) {
        return [NetUtils]::IsIpUp($ip)
    }

    static [void] ThrowIfNotV4([System.Net.IPAddress]$ip) {
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            [NetUtils]::ComplainAndThrow("IP address '$ip' is not v4, and this script doesn't support other versions.")
        }
    }

    static [System.Net.IPAddress] GetNetworkIp([System.Net.IPAddress]$someIp, [System.Net.IPAddress]$netmask) {
        [UInt32]$someIpInt = [NetUtils]::ToInt($someIp)
        [UInt32]$netmaskInt = [NetUtils]::ToInt($netmask)

        [UInt32]$networkIpInt = $someIpInt -band $netmaskInt

        return [NetUtils]::ToIp($networkIpInt)
    }

    static [System.Net.IPAddress] GetBroadcastIp([System.Net.IPAddress]$someIp, [System.Net.IPAddress]$netmask) {

        [UInt32]$networkIpInt = [NetUtils]::ToInt([NetUtils]::GetNetworkIp($someIp, $netmask))
        [UInt32]$netmaskInt = [NetUtils]::ToInt($netmask)

        [UInt32]$broadcastIpInt = $networkIpInt -bor -bnot $netmaskInt

        return [NetUtils]::ToIp($broadcastIpInt)
    }

    static [System.Net.IPAddress] GetFirstValidHostIp([System.Net.IPAddress]$networkIp) {
        return [NetUtils]::PlusOne($networkIp)
    }

    static [System.Net.IPAddress] GetLastValidHostIp([System.Net.IPAddress]$someIp, [System.Net.IPAddress]$netmask) {

        return [NetUtils]::MinusOne([NetUtils]::GetBroadcastIp($someIp, $netmask))
    }

    static [void] ThrowIfNetworkAddressAndNetmaskDisagree([System.Net.IPAddress]$networkIp, [System.Net.IPAddress]$netmask) {
        
        [UInt32]$networkIpInt = [NetUtils]::ToInt($networkIp)
        [UInt32]$netmaskInt = [NetUtils]::ToInt($netmask)

        [UInt32]$correctNetworkIpInt = $networkIpInt -band $netmaskInt

        if ($correctNetworkIpInt -ne $networkIpInt) {

            [System.Net.IPAddress]$networkIp = [NetUtils]::ToIp($networkIpInt)
            [System.Net.IPAddress]$netmask = [NetUtils]::ToIp($netmaskInt)
            [System.Net.IPAddress]$correctNetworkIp = [NetUtils]::ToIp($correctNetworkIpInt)

            [NetUtils]::ComplainAndThrow("address '$networkIp' was given, but this does not align with given netmask '$netmask'. Did you mean '$correctNetworkIp'?")
        }
    }

    static [string[]] GetTableEntryForIp([System.Net.IPAddress]$ip) {
        [string[]]$output = arp -a $ip.ToString()
        return $output
    }

    static [bool] IpHasMAC([System.Net.IPAddress]$ip, [string]$mac) {

        [bool]$foundIp = [NetUtils]::AddToMACLookupTable($ip)
        if (-not $foundIp) {
            return $false
        }

        [string[]]$arpStr = [NetUtils]::GetTableEntryForIp($ip)
        return ($arpStr | Select-String -Quiet "$mac")
    }

}
