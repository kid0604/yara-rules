rule Ransom_Alfa
{
	meta:
		description = "Regla para detectar W32/Filecoder.Alfa (Posibles falsos positivos)"
		author = "CCN-CERT"
		version = "1.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 8B 0C 97 81 E1 FF FF 00 00 81 F9 19 04 00 00 74 0F 81 F9 }
		$b = { 22 04 00 00 74 07 42 3B D0 7C E2 EB 02 }

	condition:
		all of them
}
