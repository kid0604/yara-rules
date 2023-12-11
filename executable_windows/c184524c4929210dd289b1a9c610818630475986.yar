import "pe"

rule WarningmaybeSimbyOZpolycryptorby3xpl01tver2xx250320072200
{
	meta:
		author = "malware-lu"
		description = "Detects potential presence of Simby.OZpolycryptor malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 57 57 8D 7C 24 04 50 B8 00 D0 17 13 AB 58 5F C3 00 00 }

	condition:
		$a0 at pe.entry_point
}
