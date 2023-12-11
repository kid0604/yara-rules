import "pe"

rule Fusion10jaNooNi
{
	meta:
		author = "malware-lu"
		description = "Detects Fusion10jaNooNi malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00 }

	condition:
		$a0 at pe.entry_point
}
