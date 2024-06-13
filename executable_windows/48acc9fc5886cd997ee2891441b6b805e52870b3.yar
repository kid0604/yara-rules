rule Windows_Generic_Threat_1f2e969c
{
	meta:
		author = "Elastic Security"
		id = "1f2e969c-5d90-4bab-a06a-9cccb1946251"
		fingerprint = "e7c872f2422fe54367900d69c9bb94d86db2bf001cbbe00ba6c801fb3d1e610e"
		creation_date = "2024-06-05"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "7def75df729ed66511fbe91eadf15bc69a03618e78c48e27c35497db2a6a97ae"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 53 8B 5A 10 56 8B F1 57 6A 78 89 75 FC C7 46 10 00 00 00 00 C7 46 14 0F 00 00 00 53 89 75 FC C6 06 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 33 C0 89 7D FC 85 DB 7E 39 0F 1F 40 00 }

	condition:
		all of them
}
