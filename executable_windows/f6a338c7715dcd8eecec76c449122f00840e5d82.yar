rule Windows_Generic_Threat_20469956
{
	meta:
		author = "Elastic Security"
		id = "20469956-1be6-48e8-b3c4-5706f9630971"
		fingerprint = "67cec754102e3675b4e72ff4826c40614e4856b9cbf12489de3406318990fc85"
		creation_date = "2023-12-18"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "a1f2923f68f5963499a64bfd0affe0a729f5e7bd6bcccfb9bed1d62831a93c47"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 E4 F8 83 EC 5C 53 56 33 C0 C7 44 24 18 6B 00 6C 00 57 8D 4C 24 1C C7 44 24 20 69 00 66 00 C7 44 24 24 2E 00 73 00 C7 44 24 28 79 00 73 00 66 89 44 24 2C C7 44 24 0C 6B 00 6C 00 C7 }

	condition:
		all of them
}
