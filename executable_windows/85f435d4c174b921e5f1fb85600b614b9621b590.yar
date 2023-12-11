import "pe"

rule MicroJoiner17coban2k
{
	meta:
		author = "malware-lu"
		description = "Detects the MicroJoiner17coban2k malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
