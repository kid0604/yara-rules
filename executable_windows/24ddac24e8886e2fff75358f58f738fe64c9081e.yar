import "pe"

rule EXECryptor224StrongbitSoftCompleteDevelopmenth2
{
	meta:
		author = "malware-lu"
		description = "Detects EXECryptor 2.24 StrongbitSoft Complete Developmenth2"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 F7 FE FF FF 05 [2] 00 00 FF E0 E8 EB FE FF FF 05 [2] 00 00 FF E0 E8 ?? 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
