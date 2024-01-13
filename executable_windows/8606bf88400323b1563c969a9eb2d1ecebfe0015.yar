rule Windows_Generic_Threat_24191082
{
	meta:
		author = "Elastic Security"
		id = "24191082-58a7-4d1e-88d2-b4935ba5a868"
		fingerprint = "6bf991b391b79e897fe7964499e7e86b7b8fe4f40cf17abba85cb861e840e082"
		creation_date = "2023-12-20"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "4d20878c16d2b401e76d8e7c288cf8ef5aa3c8d4865f440ee6b44d9f3d0cbf33"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 8B 45 0C 48 F7 D0 23 45 08 5D C3 55 8B EC 51 8B 45 0C 48 23 45 08 74 15 FF 75 0C FF 75 08 E8 DA FF FF FF 59 59 03 45 0C 89 45 FC EB 06 8B 45 08 89 45 FC 8B 45 FC 8B E5 5D C3 55 8B EC }

	condition:
		all of them
}
