import "pe"

rule PEPackv099
{
	meta:
		author = "malware-lu"
		description = "Detects the PEPack version 0.99"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 83 ED 06 80 BD E0 04 [2] 01 0F 84 F2 }

	condition:
		$a0 at pe.entry_point
}
