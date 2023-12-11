import "pe"

rule ACProtectUltraProtect10X20XRiSco
{
	meta:
		author = "malware-lu"
		description = "Detects ACProtect, UltraProtect, 10X, 20X, and RiSco packers"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [12] 00 00 00 00 00 00 00 00 [13] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [16] 00 00 00 00 55 53 45 52 33 32 2E 44 4C 4C 00 [4] 00 00 00 00 [20] 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 6F 72 74 5F 45 6E 64 73 73 00 }

	condition:
		$a0
}
