import "pe"

rule MALWARE_Win_NPlusMiner
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell based NPlusMiner"
		snort_sid = "920284"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$Core | Add-Member @{IsReadOnly = $((Get-ItemProperty -Path \".\\Includes\\Core.ps1\").IsReadOnly)} -Force" fullword ascii
		$s2 = "$Core | Add-Member @{MinerCustomConfig = $((Get-Content \".\\Config\\MinerCustomConfig.json\" -Raw))} -Force" fullword ascii
		$s3 = "If ($Variables.CheatGuy -and $Core.corehash -in $Hashes -and $Core.ScriptStartDate -le (Get-Date)" ascii
		$s4 = "Try{(Get-ItemProperty -Path \".\\Includes\\Core.ps1\").IsReadOnly = $false} catch {}" fullword ascii
		$s5 = " NPlusMiner/" ascii

	condition:
		3 of them
}
