import "pe"

rule SLVc0deProtector060SLVICU
{
	meta:
		author = "malware-lu"
		description = "Detects SLVc0de Protector 060SLVICU"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD }

	condition:
		$a0
}
