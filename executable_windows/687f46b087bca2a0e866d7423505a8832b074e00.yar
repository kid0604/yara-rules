import "pe"

rule EZIPv10
{
	meta:
		author = "malware-lu"
		description = "Detects the EZIPv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C }

	condition:
		$a0 at pe.entry_point
}
