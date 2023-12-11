import "pe"

rule WinUpackv039finalrelocatedimagebaseByDwingc2005h2
{
	meta:
		author = "malware-lu"
		description = "Detects WinUpack v0.39 final with relocated image base"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 09 00 00 00 [3] 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 }

	condition:
		$a0 at pe.entry_point
}
