rule Linux_Cryptominer_Xmrminer_d1bb752f
{
	meta:
		author = "Elastic Security"
		id = "d1bb752f-f5d6-4d93-96af-d977b501776a"
		fingerprint = "0f2455a4e80d93e7f1e420dc2f36e89c28ecb495879bca2e683a131b2770c3ee"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { F8 12 48 29 C8 48 2B 83 B0 00 00 00 48 C1 E8 03 48 F7 E2 48 8B }

	condition:
		all of them
}
