import "pe"

rule WinRAR32bitSFXModule
{
	meta:
		author = "malware-lu"
		description = "Detects 32-bit SFX module of WinRAR"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [2] 00 00 00 00 00 00 90 90 90 [6] 00 ?? 00 [5] FF }

	condition:
		$a0 at pe.entry_point
}
