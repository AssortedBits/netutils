using module ./Misc.psm1

#requires -version 7


class NetUtils {

    static [UInt32] ToInt([System.Collections.BitArray]$bits) {
        return [NetUtils]::ToInt([NetUtils]::ToBytes($bits))
    }

    static [UInt32] ToInt([byte[]]$bytesIn) {

        if ($bytesIn.Length -ne 4) {
            [Misc]::ComplainAndThrow("refusing to convert an array of " + $bytesIn.Length.ToString() + " bytes to a 4-byte int")
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
            [Misc]::ComplainAndThrow("prefix length of a subnet cannot be more than 32")
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

    static [void] ThrowIfNotV4([System.Net.IPAddress]$ip) {
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            [Misc]::ComplainAndThrow("IP address '$ip' is not v4, and this script doesn't support other versions.")
        }
    }


}
