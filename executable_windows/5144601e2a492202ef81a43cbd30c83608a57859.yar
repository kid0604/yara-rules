import "pe"

rule BeRoEXEPackerv100LZMABeRoFarbrausch
{
	meta:
		author = "malware-lu"
		description = "Detects the BeRoEXEPackerv100LZMABeRoFarbrausch packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 68 [4] 68 [4] 68 [4] E8 [4] BE [4] B9 04 00 00 00 8B F9 81 FE [4] 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }

	condition:
		$a0 at pe.entry_point
}
