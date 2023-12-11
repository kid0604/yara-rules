import "pe"

rule Kryptonv05
{
	meta:
		author = "malware-lu"
		description = "Detects Kryptonv05 malware by analyzing the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 54 E8 [4] 5D 8B C5 81 ED 71 44 [2] 2B 85 64 60 [2] EB 43 DF }

	condition:
		$a0 at pe.entry_point
}
