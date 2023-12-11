import "pe"

rule SVKProtectorv132
{
	meta:
		author = "malware-lu"
		description = "Detects SVKProtector v1.32 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 }

	condition:
		$a0 at pe.entry_point
}
