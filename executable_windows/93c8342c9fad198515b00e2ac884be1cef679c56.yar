import "pe"

rule RLPackFullEditionV11Xap0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack Full Edition v11 Xap0x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 [24] 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 10 }

	condition:
		$a0
}
