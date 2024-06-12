rule Linux_Generic_Threat_da28eb8b
{
	meta:
		author = "Elastic Security"
		id = "da28eb8b-7176-4415-9c58-5f74da70f53d"
		fingerprint = "490b6a89ea704a25d0e21dfb9833d56bc26f93c788efb7fcbfe38544696d0dfd"
		creation_date = "2024-05-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "b3b4fcd19d71814d3b4899528ee9c3c2188e4a7a4d8ddb88859b1a6868e8433f"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 4A 66 67 67 6C 6A 7D 60 66 67 33 29 62 6C 6C 79 24 68 65 60 }
		$a2 = { 48 6A 6A 6C 79 7D 33 29 7D 6C 71 7D 26 61 7D 64 65 25 68 79 79 65 60 6A 68 7D 60 66 67 26 71 61 7D 64 65 22 71 64 65 25 68 79 79 65 60 6A 68 7D 60 66 67 26 71 64 65 32 78 34 39 27 30 25 60 64 68 6E 6C 26 7E 6C 6B 79 25 23 26 23 32 78 34 39 27 31 }

	condition:
		all of them
}
