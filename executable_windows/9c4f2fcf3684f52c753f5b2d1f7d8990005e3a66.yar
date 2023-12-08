import "pe"

rule UPXShit006
{
	meta:
		author = "malware-lu"
		description = "Detects UPX packed files with specific entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [2] 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }

	condition:
		$a0 at pe.entry_point
}
