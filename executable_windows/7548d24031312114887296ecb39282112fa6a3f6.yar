import "pe"

rule SLVc0deProtector11xSLVICU
{
	meta:
		author = "malware-lu"
		description = "Detects SLVc0de Protector 1.1 by SLVICU"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C [2] 00 }

	condition:
		$a0 at pe.entry_point
}
