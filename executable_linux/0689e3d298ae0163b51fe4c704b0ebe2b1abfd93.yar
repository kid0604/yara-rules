rule Linux_Cryptominer_Stak_ae8b98a9
{
	meta:
		author = "Elastic Security"
		id = "ae8b98a9-cc25-4606-a775-1129e0f08c3b"
		fingerprint = "0b5da501c97f53ecd79d708d898d4f5baae3c5fd80a4c39b891a952c0bcc86e5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Stak"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Stak malware"
		filetype = "executable"

	strings:
		$a = { D1 73 5A 49 8B 06 48 8B 78 08 4C 8B 10 4C 8D 4F 18 4D 89 CB 49 }

	condition:
		all of them
}
