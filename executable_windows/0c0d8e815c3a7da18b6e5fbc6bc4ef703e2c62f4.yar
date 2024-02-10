rule Windows_Generic_Threat_fdbcd3f2
{
	meta:
		author = "Elastic Security"
		id = "fdbcd3f2-17e6-49d4-997b-91e6a85e4226"
		fingerprint = "2a69deed3fe05b64cb37881ce50cae8972e7a610fd32c4b7f9155409bc5b297c"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "9258e4fe077be21ad7ae348868f1ac6226f6e9d404c664025006ab4b64222369"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 C4 FC 60 8B 75 0C 8D A4 24 00 00 00 00 8D A4 24 00 00 00 00 90 56 E8 22 00 00 00 0B C0 75 05 89 45 FC EB 11 89 35 84 42 40 00 46 8B 5D 08 38 18 75 E3 89 45 FC 61 8B 45 FC C9 C2 08 }

	condition:
		all of them
}
