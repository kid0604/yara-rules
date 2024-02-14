rule Linux_Generic_Threat_902cfdc5
{
	meta:
		author = "Elastic Security"
		id = "902cfdc5-7f71-4661-af17-9f3dd9b21daa"
		fingerprint = "d692401d70f20648e9bb063fc8f0e750349671e56a53c33991672d29eededcb4"
		creation_date = "2024-01-23"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat based on specific file signatures"
		filetype = "executable"

	strings:
		$a1 = { 54 65 67 73 6B 54 47 66 42 7A 4C 35 5A 58 56 65 41 54 4A 5A 2F 4B 67 34 67 47 77 5A 4E 48 76 69 5A 49 4E 50 49 56 70 36 4B 2F 2D 61 77 33 78 34 61 6D 4F 57 33 66 65 79 54 6F 6D 6C 71 37 2F 57 58 6B 4F 4A 50 68 41 68 56 50 74 67 6B 70 47 74 6C 68 48 }

	condition:
		all of them
}
