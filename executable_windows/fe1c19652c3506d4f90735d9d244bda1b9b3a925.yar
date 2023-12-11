import "pe"

rule MALWARE_Win_GENERIC01
{
	meta:
		author = "ditekSHen"
		description = "Detects known unamed malicious executables, mostly DLLs"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\wmkawe_%d.data" ascii
		$s2 = "\\resmon.resmoncfg" ascii
		$s3 = "ByPassUAC" fullword ascii
		$s4 = "rundll32.exe C:\\ProgramData\\Sandboxie\\SbieMsg.dll,installsvc" fullword ascii nocase
		$s5 = "%s\\SbieMsg." ascii
		$s6 = "Stupid Japanese" fullword ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
