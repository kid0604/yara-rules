import "pe"

rule kryptor9
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Kryptor9 malware based on specific strings at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5E B9 [4] 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

	condition:
		$a0 at pe.entry_point
}
