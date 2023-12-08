import "pe"

rule AppProtectorSilentTeam
{
	meta:
		author = "malware-lu"
		description = "Detects AppProtectorSilentTeam malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A }

	condition:
		$a0 at pe.entry_point
}
