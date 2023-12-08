import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_DisableWinDefender
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing artifcats associated with disabling Widnows Defender"
		os = "windows"
		filetype = "executable"

	strings:
		$reg1 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
		$reg2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
		$s1 = "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" ascii wide nocase
		$s2 = "Set-MpPreference -DisableArchiveScanning $true" ascii wide nocase
		$s3 = "Set-MpPreference -DisableIntrusionPreventionSystem $true" ascii wide nocase
		$s4 = "Set-MpPreference -DisableScriptScanning $true" ascii wide nocase
		$s5 = "Set-MpPreference -SubmitSamplesConsent 2" ascii wide nocase
		$s6 = "Set-MpPreference -MAPSReporting 0" ascii wide nocase
		$s7 = "Set-MpPreference -HighThreatDefaultAction 6" ascii wide nocase
		$s8 = "Set-MpPreference -ModerateThreatDefaultAction 6" ascii wide nocase
		$s9 = "Set-MpPreference -LowThreatDefaultAction 6" ascii wide nocase
		$s10 = "Set-MpPreference -SevereThreatDefaultAction 6" ascii wide nocase
		$s11 = "Set-MpPreference -EnableControlledFolderAccess Disabled" ascii wide nocase
		$pdb = "\\Disable-Windows-Defender\\obj\\Debug\\Disable-Windows-Defender.pdb" ascii
		$e1 = "Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
		$e2 = "Add-MpPreference -Exclusion" ascii wide nocase
		$c1 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4" ascii wide

	condition:
		uint16(0)==0x5a4d and ((1 of ($reg*) and 1 of ($s*)) or ($pdb) or all of ($e*) or #c1>1)
}
