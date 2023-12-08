import "pe"

rule tElock099tE
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElock099tE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 5E DF FF FF 00 00 00 [4] E5 [2] 00 00 00 00 00 00 00 00 00 05 }

	condition:
		$a0 at pe.entry_point
}
