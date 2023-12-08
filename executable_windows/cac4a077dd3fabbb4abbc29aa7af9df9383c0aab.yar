import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableWinDefender
{
	meta:
		author = "ditekSHen"
		description = "Detects executables embedding registry key / value combination indicative of disabling Windows Defedner features"
		os = "windows"
		filetype = "executable"

	strings:
		$r1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
		$k1 = "DisableAntiSpyware" ascii wide
		$r2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
		$k2 = "DisableBehaviorMonitoring" ascii wide
		$k3 = "DisableOnAccessProtection" ascii wide
		$k4 = "DisableScanOnRealtimeEnable" ascii wide
		$r3 = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
		$k5 = "vDisableRealtimeMonitoring" ascii wide
		$r4 = "SOFTWARE\\Microsoft\\Windows Defender\\Spynet" ascii wide nocase
		$k6 = "SpyNetReporting" ascii wide
		$k7 = "SubmitSamplesConsent" ascii wide
		$r5 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
		$k8 = "TamperProtection" ascii wide
		$r6 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
		$k9 = "Add-MpPreference -ExclusionPath \"{0}\"" ascii wide

	condition:
		uint16(0)==0x5a4d and (1 of ($r*) and 1 of ($k*))
}
