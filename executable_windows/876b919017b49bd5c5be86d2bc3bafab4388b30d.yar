rule Windows_Generic_Threat_2f726f2d
{
	meta:
		author = "Elastic Security"
		id = "2f726f2d-4abe-47c9-9935-cd66e8c6b4cd"
		fingerprint = "2bda0cada0024df1d364d8c45bff7464e6deed015e989fcdff2a9e7baeab4192"
		creation_date = "2024-10-11"
		last_modified = "2024-11-26"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "ede9bd928a216c9844f290be0de6985ed54dceaff041906dca3a3468293464b6"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 83 EC 0C 89 4D F8 8B 45 F8 83 78 08 00 75 04 32 C0 EB 26 ?? ?? ?? ?? ?? ?? 89 4D F4 6A 00 8B 55 F8 8B 42 08 50 FF 55 F4 85 C0 74 06 C6 45 FF 01 EB 04 C6 45 FF 00 8A 45 FF 8B E5 5D C3 }

	condition:
		all of them
}
