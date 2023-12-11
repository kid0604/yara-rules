import "pe"

rule ASPackv2xxAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v2.xx by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
		$a1 = { A8 03 [2] 61 75 08 B8 01 [3] C2 0C ?? 68 [4] C3 8B 85 26 04 [2] 8D 8D 3B 04 [2] 51 50 FF 95 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
