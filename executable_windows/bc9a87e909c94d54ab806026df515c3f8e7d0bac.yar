import "pe"

rule NsPacKV37LiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D [4] ?? 80 39 01 0F [3] 00 00 }

	condition:
		$a0 at pe.entry_point
}
