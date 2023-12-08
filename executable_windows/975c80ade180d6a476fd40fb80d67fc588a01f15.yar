import "pe"

rule PCShrink071beta
{
	meta:
		author = "malware-lu"
		description = "Detects PCShrink071beta malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }

	condition:
		$a0 at pe.entry_point
}
