using module ./Misc.psm1
using module ./NetUtils.psm1

#requires -version 7


class Subnet {

    [System.Collections.BitArray]$networkBits

    Subnet([System.Collections.BitArray]$arr) {
        if ($arr.Count -gt 32 ) {
            [Misc]::ComplainAndThrow("input bit array had length " + $arr.Count + ", but an IPv4 subnet may not have more than 32 bits.")
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

    [uint] GetNumNetmaskBits() {
        return $this.networkBits.Count
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
            [Misc]::ComplainAndThrow("network address '$networkIp' was given, but this violates prefix length '$prefixLength'.")
        }
    }

    static [Subnet] FromCIDR([string]$cidr) {

        [string]$errStr = "input subnet '$cidr' is not in CIDR format -- e.g. 192.168.1.0/24"

        [string[]]$parts = $Cidr -split '/'
        if ($parts.Count -ne 2) {
            [Misc]::ComplainAndThrow($errStr)
        }

        [System.Net.IPAddress]$networkAddress = [System.Net.IPAddress]::Parse($parts[0])
        [NetUtils]::ThrowIfNotV4($networkAddress)

        [byte]$prefixLength = [Byte]::Parse($parts[1])
        if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
            [Misc]::ComplainAndThrow("Invalid prefix length: $prefixLength")
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

    static [Subnet[]] Current() {

        return (
            Get-NetIPConfiguration |
            Where-Object { $null -ne $_.IPv4DefaultGateway } |
            Where-Object { $_.NetAdapter.Status -eq "Up" } |
            Select-Object -ExpandProperty IPv4Address |
            ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" } |
            ForEach-Object { [Subnet]::FromCIDR($_) } )
    }

    [string] ToCIDR() {
        return ($this.GetNetworkAddress().ToString() + "/" + $this.GetNumNetmaskBits())
    }

}
