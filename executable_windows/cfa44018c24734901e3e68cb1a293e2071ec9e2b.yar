import "pe"

rule UpackV010V011Dwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Upack v010 or v011 Dwing packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [4] AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 ?? F3 AB C1 E0 ?? B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C ?? 73 ?? B0 ?? 3C ?? 72 02 2C ?? 50 0F B6 5F FF C1 E3 ?? B3 ?? 8D 1C 5B 8D [6] B0 ?? 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 }

	condition:
		$a0 at pe.entry_point
}
