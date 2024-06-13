rule Windows_Generic_Threat_e691eaa1
{
	meta:
		author = "Elastic Security"
		id = "e691eaa1-06fa-478e-8c4c-95a7df3fd077"
		fingerprint = "b940eb10e338f6d703a75cd77b4b455503ae0583f5a36b8115e659d05990fc3c"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "afa5f36860e69b9134b93e9ad32fed0a5923772e701437e1054ea98e76f28a77"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 8B C2 53 89 45 FC 8B D9 56 99 33 F6 2B C2 57 8B F8 D1 FF 85 FF 7E 2B 8B 55 FC 4A 03 D3 0F B6 02 8D 52 FF 8A 0C 1E ?? ?? ?? ?? ?? ?? ?? 88 04 1E 46 0F B6 C1 }

	condition:
		all of them
}
