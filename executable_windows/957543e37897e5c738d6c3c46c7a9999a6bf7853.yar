import "pe"

rule EXEStealthv274WebToolMaster
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the EXEStealth v2.74 Web Tool Master malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 00 EB 17 [23] 60 90 E8 00 00 00 00 5D }

	condition:
		$a0 at pe.entry_point
}
