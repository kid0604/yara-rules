rule Linux_Generic_Threat_6d7ec30a
{
	meta:
		author = "Elastic Security"
		id = "6d7ec30a-5c9f-4d82-8191-b26eb2f40799"
		fingerprint = "7d547a73a44eab080dde9cd3ff87d75cf39d2ae71d84a3daaa6e6828e057f134"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "1cad1ddad84cdd8788478c529ed4a5f25911fb98d0a6241dcf5f32b0cdfc3eb0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2F 74 6D 70 2F 73 6F 63 6B 73 35 2E 73 68 }
		$a2 = { 63 61 74 20 3C 28 65 63 68 6F 20 27 40 72 65 62 6F 6F 74 20 65 63 68 6F 20 73 6F 63 6B 73 35 5F 62 61 63 6B 63 6F 6E 6E 65 63 74 36 36 36 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 7C 20 28 63 64 20 20 26 26 20 29 27 29 20 3C 28 73 65 64 20 27 2F 73 6F 63 6B 73 35 5F 62 61 63 6B 63 6F 6E 6E 65 63 74 36 36 36 2F 64 27 20 3C 28 63 72 6F 6E 74 61 62 20 2D 6C 20 32 3E 2F 64 65 76 2F 6E 75 6C 6C 29 29 20 7C 20 63 72 6F 6E 74 61 62 20 2D }

	condition:
		all of them
}
