rule Windows_Generic_Threat_994f2330
{
	meta:
		author = "Elastic Security"
		id = "994f2330-ce61-4c23-b100-7df3feaeb078"
		fingerprint = "4749717da2870a3942d7a3aa7e2809c4b9dc783a484bfcd2ce7416ae67164a26"
		creation_date = "2023-12-18"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "0a30cb09c480a2659b6f989ac9fe1bfba1802ae3aad98fa5db7cdd146fee3916"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 0C 8B 55 08 85 D2 0F 84 C7 00 00 00 8B 42 3C 83 7C 10 74 10 8D 44 10 18 0F 82 B5 00 00 00 83 78 64 00 0F 84 AB 00 00 00 8B 4D 0C 8B 40 60 C1 E9 10 03 C2 66 85 C9 75 14 0F B7 4D }

	condition:
		all of them
}
