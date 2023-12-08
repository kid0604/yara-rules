import "pe"

rule BeRoEXEPackerv100LZBRSBeRoFarbrausch
{
	meta:
		author = "malware-lu"
		description = "Detects the BeRoEXEPackerv100LZBRSBeRoFarbrausch packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BE [4] BF [4] FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 [4] 72 03 A4 EB F2 E8 [4] 8D 51 FF E8 [4] 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }

	condition:
		$a0 at pe.entry_point
}
