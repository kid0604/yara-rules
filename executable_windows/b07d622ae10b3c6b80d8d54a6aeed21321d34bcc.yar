import "pe"

rule Winkriptv10
{
	meta:
		author = "malware-lu"
		description = "Detects the Winkriptv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 C0 8B B8 00 [3] 8B 90 04 [3] 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }

	condition:
		$a0 at pe.entry_point
}
