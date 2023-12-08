import "pe"

rule eXPressor11CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor11CGSoftLabs malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [2] 00 00 E9 [2] 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 [2] 00 00 E9 [2] 00 00 E9 [2] 00 00 }

	condition:
		$a0 at pe.entry_point
}
