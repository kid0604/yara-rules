import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_SandboxHookingDLL
{
	meta:
		description = "Detects binaries and memory artifcats referencing sandbox DLLs typically observed in sandbox evasion"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$dll1 = "sbiedll.dll" nocase fullword ascii wide
		$dll3 = "api_log.dll" nocase fullword ascii wide
		$dll4 = "pstorec.dll" nocase fullword ascii wide
		$dll5 = "dir_watch.dll" nocase fullword ascii wide
		$dll6 = "vmcheck.dll" nocase fullword ascii wide
		$dll7 = "wpespy.dll" nocase fullword ascii wide
		$dll8 = "SxIn.dll" nocase fullword ascii wide
		$dll9 = "Sf2.dll" nocase fullword ascii wide
		$dll10 = "deploy.dll" nocase fullword ascii wide
		$dll11 = "avcuf32.dll" nocase fullword ascii wide
		$dll12 = "BgAgent.dll" nocase fullword ascii wide
		$dll13 = "guard32.dll" nocase fullword ascii wide
		$dll14 = "wl_hook.dll" nocase fullword ascii wide
		$dll15 = "QOEHook.dll" nocase fullword ascii wide
		$dll16 = "a2hooks32.dll" nocase fullword ascii wide
		$dll17 = "tracer.dll" nocase fullword ascii wide
		$dll18 = "APIOverride.dll" nocase fullword ascii wide
		$dll19 = "NtHookEngine.dll" nocase fullword ascii wide
		$dll20 = "LOG_API.DLL" nocase fullword ascii wide
		$dll21 = "LOG_API32.DLL" nocase fullword ascii wide
		$dll22 = "vmcheck32.dll" nocase ascii wide
		$dll23 = "vmcheck64.dll" nocase ascii wide
		$dll24 = "cuckoomon.dll" nocase ascii wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
