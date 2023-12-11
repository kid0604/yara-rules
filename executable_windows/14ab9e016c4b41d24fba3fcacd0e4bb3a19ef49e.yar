import "pe"

rule ThemidaOreansTechnologies2004
{
	meta:
		author = "malware-lu"
		description = "Detects Themida or Oreans Technologies 2004 packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 }

	condition:
		$a0 at pe.entry_point
}
