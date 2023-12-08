import "pe"

rule AINEXEv230
{
	meta:
		author = "malware-lu"
		description = "Detects AINEXEv230 malware at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0E 07 B9 [2] BE [2] 33 FF FC F3 A4 A1 [2] 2D [2] 8E D0 BC [2] 8C D8 }

	condition:
		$a0 at pe.entry_point
}
