import "pe"

rule Excalibur103forgot
{
	meta:
		author = "malware-lu"
		description = "Detects Excalibur103 malware that may have forgotten to clean up after itself"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
