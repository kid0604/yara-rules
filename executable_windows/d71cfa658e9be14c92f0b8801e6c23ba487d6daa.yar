import "pe"

rule EnigmaProtector131Build20070615DllSukhovVladimirSergeNMarkin
{
	meta:
		author = "malware-lu"
		description = "Detects Enigma Protector version 1.31 Build 20070615 DLL by Sukhov Vladimir Serge N Markin"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 81 ED [4] E9 49 00 00 00 [40] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8A 84 24 28 00 00 00 80 F8 01 0F 84 07 00 00 00 B8 [4] FF E0 E9 04 00 00 00 [4] B8 [4] 03 C5 81 C0 [4] B9 [4] BA [4] 30 10 40 49 0F 85 F6 FF FF FF E9 04 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
