import "pe"

rule NsPacKV34V35LiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 [4] 80 38 01 0F 84 }

	condition:
		$a0 at pe.entry_point
}
