import "pe"

rule RODHighTECHAyman
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RODHighTECHAyman malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00 }

	condition:
		$a0 at pe.entry_point
}
