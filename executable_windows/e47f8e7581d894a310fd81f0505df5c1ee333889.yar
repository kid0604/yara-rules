import "pe"

rule MALWARE_Win_CyberGate
{
	meta:
		author = "ditekSHen"
		description = "Detects CyberGate/Spyrat/Rebhip RTA"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UnitInjectLibrary" ascii
		$s2 = "TLoader" fullword ascii
		$s3 = "\\\\.\\SyserDbgMsg" fullword ascii
		$s4 = "\\\\.\\SyserBoot" fullword ascii
		$s5 = "\\signons" ascii
		$s6 = "####@####" ascii
		$s7 = "XX-XX-XX-XX" fullword ascii
		$s8 = "EditSvr" ascii
		$s9 = "_x_X_PASSWORDLIST_X_x_" fullword ascii
		$s10 = "L$_RasDefaultCredentials#0" fullword ascii
		$s11 = "password" nocase ascii

	condition:
		uint16(0)==0x5a4d and 8 of them
}
