import "pe"

rule Obsiduim1304ObsiduimSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects Obsiduim software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04 [4] 64 67 FF 36 00 00 EB 03 [3] 64 }

	condition:
		$a0 at pe.entry_point
}
