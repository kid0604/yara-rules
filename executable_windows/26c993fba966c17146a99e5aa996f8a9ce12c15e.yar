import "pe"

rule kkrunchyRyd
{
	meta:
		author = "malware-lu"
		description = "Detects the kkrunchyRyd malware based on its entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BD 08 [2] 00 C7 45 00 [3] 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF [3] 00 57 BE [3] 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 }

	condition:
		$a0 at pe.entry_point
}
