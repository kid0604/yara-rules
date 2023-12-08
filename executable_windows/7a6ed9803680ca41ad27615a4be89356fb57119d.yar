import "pe"

rule EXEStealthv271
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the EXEStealth v2.71 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40 }

	condition:
		$a0 at pe.entry_point
}
