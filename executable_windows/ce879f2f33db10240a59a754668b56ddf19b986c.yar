import "pe"

rule RSCsProcessPatcherv14
{
	meta:
		author = "malware-lu"
		description = "Detects RSCsProcessPatcherv14 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 }

	condition:
		$a0
}
