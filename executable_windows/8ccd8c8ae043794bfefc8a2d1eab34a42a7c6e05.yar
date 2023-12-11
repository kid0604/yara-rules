import "pe"

rule Upack021betaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack 0.21 beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 }

	condition:
		$a0 at pe.entry_point
}
