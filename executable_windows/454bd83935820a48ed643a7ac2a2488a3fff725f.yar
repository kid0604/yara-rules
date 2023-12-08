import "pe"

rule EXECryptor224StrongbitSoftCompleteDevelopmenth1
{
	meta:
		author = "malware-lu"
		description = "Detects EXECryptor 2.24 StrongbitSoft Complete Developmenth1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 F7 FE FF FF 05 [2] 00 00 FF E0 E8 EB FE FF FF 05 [2] 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }

	condition:
		$a0 at pe.entry_point
}
