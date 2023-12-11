import "pe"

rule AHPack01FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of AHPack01FEUERRADER malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 68 54 [2] 00 B8 48 [2] 00 FF 10 68 B3 [2] 00 50 B8 44 [2] 00 FF 10 68 00 }

	condition:
		$a0 at pe.entry_point
}
