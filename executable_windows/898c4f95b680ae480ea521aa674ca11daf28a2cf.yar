rule Windows_Generic_Threat_2e3c2ec5
{
	meta:
		author = "Elastic Security"
		id = "2e3c2ec5-4a95-4fea-90d0-8bf7c9cb2b27"
		fingerprint = "7900635bfb947487995d3d27fd56c47d1b4549bce6216cffc04c000811d6f4ae"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "91755a6831a4aa2d66fea9c3d6203b0ed3f1f58e0f4e1d1550aba4fe18895695"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 57 69 6E 64 6F 77 55 70 64 61 74 65 73 69 7A 65 5F 69 6E 63 72 65 6D 65 6E 74 50 6F 69 73 6F 6E 45 72 72 6F 72 57 69 6E 64 6F 77 }

	condition:
		all of them
}
