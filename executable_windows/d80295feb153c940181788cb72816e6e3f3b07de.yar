import "pe"

rule kkrunchyV02XRyd
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of kkrunchyV02XRyd malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BD [4] C7 45 [5] FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF [4] 57 BE [4] 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 }

	condition:
		$a0 at pe.entry_point
}
