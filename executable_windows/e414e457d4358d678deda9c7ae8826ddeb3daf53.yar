import "pe"

rule MALWARE_Win_DLAgent05
{
	meta:
		author = "ditekSHen"
		description = "Detects an unknown dropper. Typically exisys as a DLL in base64-encoded gzip-compressed file embedded within another executable"
		clamav_sig = "MALWARE.Win.Trojan.DLAgent05"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "MARCUS.dll" fullword ascii wide
		$s2 = "GZipStream" fullword ascii
		$s3 = "MemoryStream" fullword ascii
		$s4 = "proj_name" fullword ascii
		$s5 = "res_name" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
