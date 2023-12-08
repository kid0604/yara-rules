import "pe"

rule PseudoSigner01BorlandDelphi6070Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a Borland Delphi PseudoSigner version 01BorlandDelphi6070Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8 }

	condition:
		$a0 at pe.entry_point
}
