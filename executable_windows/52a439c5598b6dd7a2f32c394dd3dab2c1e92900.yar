import "pe"

rule MALWARE_Win_DLLLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown DLL Loader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "LondLibruryA" fullword ascii
		$s2 = "LdrLoadDll" fullword ascii
		$s3 = "snxhk.dll" fullword ascii
		$s4 = "DisableThreadLibraryCalls" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
