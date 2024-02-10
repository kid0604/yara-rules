rule Windows_Generic_Threat_5fbf5680
{
	meta:
		author = "Elastic Security"
		id = "5fbf5680-05c3-4a77-95d7-fa3cae7b4dbe"
		fingerprint = "7cbd8d973f31505e078781bed8067ae8dce72db076c670817e1a77e48dc790fe"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1b0553a9873d4cda213f5464b5e98904163e347a49282db679394f70d4571e77"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 3C 56 57 8B 45 08 50 E8 51 AF 00 00 83 C4 04 89 45 FC 8B 45 FC 83 C0 58 99 8B C8 8B F2 8B 45 08 99 2B C8 1B F2 89 4D F8 66 0F 57 C0 66 0F 13 45 EC C7 45 DC FF FF FF FF C7 45 E0 }

	condition:
		all of them
}
