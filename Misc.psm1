#requires -version 7


class Misc {

    static [string] GetSourceLocation([int]$stackDepth) {
        $callerFrame = Get-PSCallStack | Select-Object -Skip ($stackDepth + 1) -First 1
        return $callerFrame.ScriptName + ":" + $callerFrame.FunctionName + ":" + $callerFrame.Location
    }

    static [void] ComplainAndThrow([string]$errStr) {
        $errStr = "at " + [Misc]::GetSourceLocation(1) + ": " + $errStr
        Write-Host $errStr
        throw $errStr
    }

}
