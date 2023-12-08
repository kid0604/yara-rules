import "pe"

rule SVKProtectorv111
{
	meta:
		author = "malware-lu"
		description = "Detects SVKProtectorv111 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED 06 [3] 64 A0 23 }

	condition:
		$a0 at pe.entry_point
}
