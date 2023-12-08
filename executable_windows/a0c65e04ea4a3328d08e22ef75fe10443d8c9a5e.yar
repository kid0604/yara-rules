import "pe"

rule PseudoSigner01BorlandDelphi50KOLMCKAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi 5.0 KOL MCK Anorganix PseudoSigner"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 90 90 90 90 68 [4] 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
