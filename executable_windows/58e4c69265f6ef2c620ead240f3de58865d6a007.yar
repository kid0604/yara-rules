import "pe"

rule ThinstallEmbedded2547V2600Jitit
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall embedded code version 2547 v2600 Jitit"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 [4] 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00 }

	condition:
		$a0 at pe.entry_point
}
