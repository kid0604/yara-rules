rule Windows_Generic_Threat_3613fa12
{
	meta:
		author = "Elastic Security"
		id = "3613fa12-b559-4c3f-8049-11bacd5ffd0c"
		fingerprint = "c66b5dad2e9b19be0bc67a652761d8f79ce85efde055cc412575c2d7c5583795"
		creation_date = "2024-02-20"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1403ec99f262c964e3de133a10815e34d2f104b113b0197ab43c6b7b40b536c0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 89 4D FC 8D 45 08 50 8B 4D FC E8 4D 03 00 00 8B 45 FC 8B E5 5D C2 04 00 CC CC CC CC 55 8B EC 51 89 4D FC 8B 45 FC 8B E5 5D C3 CC CC 55 8B EC 51 89 4D FC 8B 45 08 50 8B 4D FC E8 FD }

	condition:
		all of them
}
