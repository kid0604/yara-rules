import "pe"

rule Petite12
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Petite12 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 }

	condition:
		$a0 at pe.entry_point
}
