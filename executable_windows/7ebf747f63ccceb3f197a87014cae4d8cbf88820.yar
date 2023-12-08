import "pe"

rule RLPackv118BasicLZMAAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPackv1.18 Basic LZMA Ap0x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }

	condition:
		$a0 at pe.entry_point
}
