import "pe"

rule AINEXEv21
{
	meta:
		author = "malware-lu"
		description = "Detects AINEXEv21 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { A1 [2] 2D [2] 8E D0 BC [2] 8C D8 36 A3 [2] 05 [2] 36 A3 [2] 2E A1 [2] 8A D4 B1 04 D2 EA FE C9 }

	condition:
		$a0 at pe.entry_point
}
