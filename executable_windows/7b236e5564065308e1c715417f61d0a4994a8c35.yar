import "pe"

rule NoodleCryptv20
{
	meta:
		author = "malware-lu"
		description = "Detects NoodleCryptv20 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }
		$a1 = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 [2] 00 00 EB 01 9A E8 [2] 00 00 EB 01 }

	condition:
		$a0 at pe.entry_point or $a1
}
