import "pe"

rule SoftWrap
{
	meta:
		author = "malware-lu"
		description = "Detects SoftWrap malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 52 53 51 56 57 55 E8 [4] 5D 81 ED 36 [3] E8 ?? 01 [2] 60 BA [4] E8 [4] 5F }

	condition:
		$a0 at pe.entry_point
}
