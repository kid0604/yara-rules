rule Windows_Generic_Threat_604a8763
{
	meta:
		author = "Elastic Security"
		id = "604a8763-7ec1-4474-b238-2ebbaf24afa2"
		fingerprint = "c74c1dc7588d01112c3995b17e9772af15fb1634ebfb417b8c0069ac1f334e74"
		creation_date = "2024-03-05"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "2a51fb11032ec011448184a4f2837d05638a7673d16dcf5dcf4005de3f87883a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 8B 45 0C 48 89 45 FC EB 07 8B 45 FC 48 89 45 FC 83 7D FC 00 7C 0B 8B 45 08 03 45 FC C6 00 00 EB E8 C9 C3 55 8B EC 83 EC 0C 8B 45 0C 89 45 FC 8B 45 08 3B 45 10 76 2F 8B 45 FC 89 45 }

	condition:
		all of them
}
