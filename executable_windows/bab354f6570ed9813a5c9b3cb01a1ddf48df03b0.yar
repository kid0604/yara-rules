import "pe"

rule Upack010012betaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upack 010012 beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 }

	condition:
		$a0 at pe.entry_point
}
