import "pe"

rule BeRoEXEPackerv100DLLLZMABeRoFarbrausch
{
	meta:
		author = "malware-lu"
		description = "Detects the BeRoEXEPackerv100DLLLZMABeRoFarbrausch packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 7C 24 08 01 0F 85 [4] 60 68 [4] 68 [4] 68 [4] E8 [4] BE [4] B9 [4] 8B F9 81 FE [4] 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }

	condition:
		$a0 at pe.entry_point
}
