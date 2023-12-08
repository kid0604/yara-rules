import "pe"

rule ExeShield36wwwexeshieldcom
{
	meta:
		author = "malware-lu"
		description = "Yara rule to detect ExeShield 3.6 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F }

	condition:
		$a0 at pe.entry_point
}
