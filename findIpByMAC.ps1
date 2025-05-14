#requires -version 7

param (
    [Parameter(Mandatory = $true)][string]$mac,
    [Parameter(Mandatory = $true)][string]$lowIp,
    [Parameter(Mandatory = $true)][byte]$hiQuad
)


class FindIpByMAC {

    static [string] Do([string]$mac, [System.Net.IPAddress]$ipRangeLow, [byte]$lastQuadHigh) {

        if ("" -eq $mac) {
            [string]$errStr = "no MAC address supplied"
            Write-Host $errStr
            throw $errStr
        }

        if ($null -eq $ipRangeLow) {
            [string]$errStr = "no IP address range lower bound supplied"
            Write-Host $errStr
            throw $errStr
        }

        if ("" -eq $lastQuadHigh) {
            [string]$errStr = "no IP address range upper bound supplied"
            Write-Host $errStr
            throw $errStr
        }

        if ($ipRangeLow.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            [string]$errStr = "lower-bound IP address is not v4, and this script doesn't support other versions."
            Write-Host $errStr
            throw $errStr
        }

        foreach ($myByte in ($ipRangeLow.GetAddressBytes() + $lastQuadHigh)) {
            if ($myByte -lt 1 -or $myByte -gt 254) {
                [string]$errStr = "input address range transgressed onto a 0 or a 255 somewhere"
                Write-Host $errStr
                throw $errStr
            }
        }

        [byte]$lastQuadLow = $ipRangeLow.GetAddressBytes()[-1]

        if ($lastQuadLow -gt $lastQuadHigh) {
            [string]$errStr = "lower bound is above upper bound"
            Write-Host $errStr
            throw $errStr
        }

        [byte[]]$firstThreeQuads = $ipRangeLow.GetAddressBytes()[0..2]

        [string[]]$foundArr = `
            $lastQuadLow..$lastQuadHigh `
        | ForEach-Object -Parallel {
            [string]$ip = [System.Net.IPAddress]::new($using:firstThreeQuads + $_).ToString()
            [bool]$foundIp = Test-Connection -Quiet -ComputerName $ip -Count 1 -TimeoutSeconds 1 2>$null
            if ($foundIp) {
                [string[]]$arpStr = arp -a $ip
                [bool]$matchesMac = $arpStr | Select-String -Quiet "$using:mac"
                if ($matchesMac) {
                    Write-Output $ip
                }
            }
        } -ThrottleLimit 20 `
        | Select-Object -First 1

        if ($foundArr.Count -lt 1) {
            Write-Host "no network device in the given IP range with given MAC responded to pings within one second"
            exit 1;
        }
        
        return $foundArr[0]
    }

}


[FindIpByMAC]::Do($mac, [System.Net.IPAddress]::Parse($lowIp), $hiQuad)

