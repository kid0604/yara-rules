import "pe"

rule PackMasterv10
{
	meta:
		author = "malware-lu"
		description = "Detects PackMaster v1.0 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
		$a1 = { 60 E8 01 [3] E8 83 C4 04 E8 01 [3] E9 5D 81 ED D3 22 40 ?? E8 04 02 [2] E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
