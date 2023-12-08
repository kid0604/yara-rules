import "pe"

rule Morphinev33SilentSoftwareSilentShieldc2005
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Morphinev33SilentSoftwareSilentShieldc2005 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 28 [3] 00 00 00 00 00 00 00 00 40 [3] 34 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C [3] 5C [3] 00 00 00 00 4C [3] 5C [3] 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 }
		$a1 = { 28 [3] 00 00 00 00 00 00 00 00 40 [3] 34 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C [3] 5C [3] 00 00 00 00 4C [3] 5C [3] 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }

	condition:
		$a0 or $a1
}
