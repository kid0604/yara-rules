import "pe"

rule NoodleCryptv200EngNoodleSpa
{
	meta:
		author = "malware-lu"
		description = "Detects NoodleCryptv200EngNoodleSpa malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02 }

	condition:
		$a0 at pe.entry_point
}
