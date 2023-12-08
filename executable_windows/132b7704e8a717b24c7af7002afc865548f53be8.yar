import "pe"

rule SoftSentryv211
{
	meta:
		author = "malware-lu"
		description = "Detects SoftSentryv211 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }

	condition:
		$a0 at pe.entry_point
}
