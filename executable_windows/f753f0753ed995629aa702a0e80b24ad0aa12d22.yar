import "pe"

rule BeRoEXEPackerv100DLLLZBRRBeRoFarbrausch
{
	meta:
		author = "malware-lu"
		description = "Detects the BeRoEXEPackerv100DLLLZBRRBeRoFarbrausch packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 7C 24 08 01 0F 85 [4] 60 BE [4] BF [4] FC B2 80 33 DB A4 B3 02 E8 [4] 73 F6 33 C9 E8 [4] 73 1C 33 C0 E8 [4] 73 23 B3 02 41 B0 10 }

	condition:
		$a0 at pe.entry_point
}
