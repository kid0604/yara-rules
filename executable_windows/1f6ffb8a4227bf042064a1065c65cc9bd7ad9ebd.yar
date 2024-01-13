rule Windows_Generic_Threat_d331d190
{
	meta:
		author = "Elastic Security"
		id = "d331d190-2b66-499e-be08-fed81e5bb5f1"
		fingerprint = "504c204dd82689bacf3875b9fd56a6a865426f3dc76de1d6d6e40c275b069d66"
		creation_date = "2023-12-20"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "6d869d320d977f83aa3f0e7719967c7e54c1bdae9ae3729668d755ee3397a96f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 83 FA 03 74 04 85 D2 75 05 E8 EE 08 00 00 B8 01 00 00 00 48 83 C4 28 C3 CC CC CC CC 56 57 48 83 EC 38 48 89 CE 8B 01 FF C8 83 F8 05 77 12 48 98 48 8D 0D D1 49 00 00 48 63 3C 81 48 }

	condition:
		all of them
}
