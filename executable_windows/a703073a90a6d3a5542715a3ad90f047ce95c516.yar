rule Windows_Generic_Threat_2ae9b09e
{
	meta:
		author = "Elastic Security"
		id = "2ae9b09e-b810-4bd2-9cb8-18b1d504eede"
		fingerprint = "13ab32abf52bca58dfac79c09882ec4cb80b606693db19813d84e625bda93549"
		creation_date = "2024-03-05"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "dc8f4784c368676cd411b7d618407c416d9e56d116dd3cd17c3f750e6cb60c40"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 51 8B 45 08 89 45 FC 8B 45 0C 89 45 F8 8B 45 0C 48 89 45 0C 83 7D F8 00 76 0F 8B 45 FC C6 00 00 8B 45 FC 40 89 45 FC EB DE 8B 45 08 C9 C3 6A 41 5A 0F B7 C1 66 3B D1 77 0C 66 83 F9 }

	condition:
		all of them
}
