import "pe"

rule ThinstallEmbedded2545Jitit
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall embedded code using Jitit"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 F2 FF FF FF 50 68 [4] 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
