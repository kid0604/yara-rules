import "pe"

rule RSCsProcessPatcherv151
{
	meta:
		author = "malware-lu"
		description = "Detects RSCsProcessPatcherv151"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 }

	condition:
		$a0
}
