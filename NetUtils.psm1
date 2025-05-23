#requires -version 7


class NetUtils {

    static [string] GetSourceLocation([int]$stackDepth) {
        $callerFrame = Get-PSCallStack | Select-Object -Skip ($stackDepth + 1) -First 1
        return $callerFrame.ScriptName + ":" + $callerFrame.FunctionName + ":" + $callerFrame.Location
    }

    static [void] ComplainAndThrow([string]$errStr) {
        $errStr = "at " + [NetUtils]::GetSourceLocation(1) + ": " + $errStr
        Write-Host $errStr
        throw $errStr
    }

    static [UInt32] ToInt([System.Collections.BitArray]$bits) {
        return [NetUtils]::ToInt([NetUtils]::ToBytes($bits))
    }

    static [UInt32] ToInt([byte[]]$bytesIn) {

        if ($bytesIn.Length -ne 4) {
            [NetUtils]::ComplainAndThrow("refusing to convert an array of " + $bytesIn.Length.ToString() + " bytes to a 4-byte int")
        }
        [byte[]]$bytes = $bytesIn.Clone()
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($bytes)
        }
        return [BitConverter]::ToUInt32($bytes)
    }

    static [UInt32] ToInt([System.Net.IPAddress]$ip) {
        [byte[]]$byteArr = $ip.GetAddressBytes()
        return [NetUtils]::ToInt($byteArr)
    }

    static [byte[]] ToBytes([UInt32]$int) {

        [byte[]]$byteArr = [BitConverter]::GetBytes($int)
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($byteArr)
        }

        return $byteArr
    }

    static [byte[]] ToBytes([System.Collections.BitArray]$bits) {

        [byte[]]$bytes = [byte[]]@()

        #BitArray constructor reverses the order of the bits in each byte.
        #So we cannot use BitArray.CopyTo(byte[], int).

        [int]$iBit = 0
        for ([int]$iByte = 0; $iBit -lt $bits.Length; $iByte++) {
            [byte]$byte = 0
            for ([int]$iBitOffset = 0; ($iBitOffset -lt 8) -and ($iBit -lt $bits.Length); $iBitOffset++, $iBit++) {
                if ($bits[$iBit]) {
                    $byte = $byte -bor ([byte](1 -shl (7 - $iBitOffset)))
                }
            }
            $bytes += $byte
        }

        return $bytes
    }

    static [byte[]] ToBytes([System.Net.IPAddress]$ip) {
        return $ip.GetAddressBytes()
    }

    static [System.Collections.BitArray] ToBits([byte[]]$bytes) {

        [bool[]]$bitsAsBools = [bool[]]@()

        #BitArray constructor reverses the order of the bits in each byte.
        #So we cannot use the BitArray(byte[]) constructor.

        for ([int]$iByte = 0; $iByte -lt $bytes.Length; $iByte++) {
            [byte]$byte = $bytes[$iByte]

            for ([int]$iBitOffset = 0; $iBitOffset -lt 8; $iBitOffset++) {
                $bitsAsBools += [byte](1 -shl (7 - $iBitOffset)) -band $byte
            }
        }

        return [System.Collections.BitArray]::new($bitsAsBools)
    }

    static [System.Collections.BitArray] ToBits([UInt32]$int) {

        return [NetUtils]::ToBits([NetUtils]::ToBytes($int))
    }

    static [System.Collections.BitArray] ToBits([System.Net.IPAddress]$ip) {

        return [NetUtils]::ToBits($ip.GetAddressBytes())
    }

    static [System.Net.IPAddress] ToIp([UInt32]$int) {
        return [System.Net.IPAddress]::new([NetUtils]::ToBytes($int))
    }

    static [System.Net.IPAddress] ToIp([byte[]]$bytes) {
        return [System.Net.IPAddress]::new($bytes)
    }

    static [System.Net.IPAddress] ToIp([System.Collections.BitArray]$bits) {
        return [System.Net.IPAddress]::new([NetUtils]::ToBytes($bits))
    }

    static [UInt32] PrefixLengthToNetmask([byte]$prefixLength) {
        if ($prefixLength -gt 32) {
            [NetUtils]::ComplainAndThrow("prefix length of a subnet cannot be more than 32")
        }

        return [UInt32](([UInt64]1 -shl $prefixLength) - 1)        
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

    static [string[]] GetTableEntryForIp([System.Net.IPAddress]$ip) {
        [string[]]$output = arp -a $ip.ToString()
        return $output
    }

    static [bool] IpHasMAC([System.Net.IPAddress]$ip, [string]$mac) {

        [bool]$foundIp = [NetUtils]::AddToMACLookupTable($ip)
        if (-not $foundIp) {
            return $false
        }

        [string]$normalizedMAC = $mac -replace ":", "-"

        [string[]]$arpStr = [NetUtils]::GetTableEntryForIp($ip)
        return ($arpStr | Select-String -Quiet "$normalizedMAC")
    }

}

class Subnet {

    [System.Collections.BitArray]$networkBits

    Subnet([System.Collections.BitArray]$arr) {
        if ($arr.Count -gt 32 ) {
            [NetUtils]::ComplainAndThrow("input bit array had length " + $arr.Count + ", but an IPv4 subnet may not have more than 32 bits.")
        }

        $this.networkBits = $arr
    }

    [byte[]] ToBytes() {
        return [NetUtils]::ToBytes($this.GetPaddedBits($false))
    }

    [System.Collections.BitArray] GetPaddedBits([bool]$padVal) {
        
        [System.Collections.BitArray]$allBits = [System.Collections.BitArray]::new(32)
        for ([int]$i = 0; $i -lt $this.networkBits.Length; $i++) {
            $allBits[$i] = $this.networkBits[$i]
        }
        for ([int]$i = $this.networkBits.Length; $i -lt $allBits.Length; $i++) {
            $allBits[$i] = $padVal
        }

        return $allBits
    }

    [System.Net.IPAddress] GetNetworkAddress() {
        return [System.Net.IPAddress]::new($this.ToBytes())
    }

    [System.Net.IPAddress] GetBroadcastAddress() {
        return `
            [System.Net.IPAddress]::new( `
                [NetUtils]::ToBytes( `
                    $this.GetPaddedBits($true)))
    }

    [System.Net.IPAddress] GetFirstValidHostIp() {

        [System.Collections.BitArray]$padded = $this.GetPaddedBits($false)

        #32 is a special case. Technically, no host IPs exist in such a subnet, but
        # conventionally this means the network address is actually a host address.
        if ($this.networkBits.Count -lt 32) {
            $padded[31] = $true
        }

        return [NetUtils]::ToIp([NetUtils]::ToBytes($padded))
    }

    [System.Net.IPAddress] GetLastValidHostIp() {

        [System.Collections.BitArray]$padded = $this.GetPaddedBits($true)

        #32 is a special case. Technically, no host IPs exist in such a subnet, but
        # conventionally this means the network address is actually a host address.
        if ($this.networkBits.Count -lt 32) {
            $padded[31] = $false
        }
        return [NetUtils]::ToIp([NetUtils]::ToBytes($padded))
    }

    static [void] ThrowIfNetworkAddressAndNetmaskDisagree([System.Net.IPAddress]$networkIp, [byte]$prefixLength) {
        
        [UInt32]$networkIpInt = [NetUtils]::ToInt($networkIp)
        [UInt32]$netmaskInt = [NetUtils]::PrefixLengthToNetmask($prefixLength)

        [UInt32]$unmaskedBitsInGivenIp = $networkIpInt -band -not $netmaskInt

        if (0 -ne $unmaskedBitsInGivenIp) {
            [NetUtils]::ComplainAndThrow("network address '$networkIp' was given, but this violates prefix length '$prefixLength'.")
        }
    }

    static [Subnet] FromCIDR([string]$cidr) {

        [string]$errStr = "input subnet '$cidr' is not in CIDR format -- e.g. 192.168.1.0/24"

        [string[]]$parts = $Cidr -split '/'
        if ($parts.Count -ne 2) {
            [NetUtils]::ComplainAndThrow($errStr)
        }

        [System.Net.IPAddress]$networkAddress = [System.Net.IPAddress]::Parse($parts[0])
        [NetUtils]::ThrowIfNotV4($networkAddress)

        [byte]$prefixLength = [Byte]::Parse($parts[1])
        if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
            throw "Invalid prefix length: $prefixLength"
        }

        [Subnet]::ThrowIfNetworkAddressAndNetmaskDisagree($networkAddress, $prefixLength)

        [System.Collections.BitArray]$allBits = [NetUtils]::ToBits([NetUtils]::ToBytes($networkAddress))

        [System.Collections.BitArray]$myNetworkBits = [System.Collections.BitArray]::new([UInt32]$prefixLength)
        for ([int]$i = 0; $i -lt $myNetworkBits.Count; $i++) {
            [bool]$val = $allBits[$i]
            $myNetworkBits[$i] = $val
        }

        return [Subnet]::new($myNetworkBits)
    }

}
