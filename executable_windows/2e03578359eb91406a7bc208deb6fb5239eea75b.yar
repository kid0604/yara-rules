import "pe"

rule VxKuku886
{
	meta:
		author = "malware-lu"
		description = "Detects VxKuku886 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 [5] 90 B4 2F CD 21 53 }

	condition:
		$a0 at pe.entry_point
}
