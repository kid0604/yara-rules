import "pe"

rule SLVc0deProtectorv06SLV
{
	meta:
		author = "malware-lu"
		description = "Detects SLVc0de Protector v0.6"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 97 11 40 00 8D B5 EF 11 40 00 B9 FE 2D 00 00 8B FE AC F8 [6] 90 }

	condition:
		$a0 at pe.entry_point
}
