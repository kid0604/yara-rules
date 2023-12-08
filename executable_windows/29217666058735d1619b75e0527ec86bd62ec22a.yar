import "pe"

rule NsPacKV30LiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [4] 66 8B 06 66 83 F8 00 74 }

	condition:
		$a0 at pe.entry_point
}
