import "pe"

rule Themida1201compressedOreansTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects Themida or Oreans Technologies compressed executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 00 00 [2] 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }

	condition:
		$a0 at pe.entry_point
}
