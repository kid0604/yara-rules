rule Linux_Cryptominer_Xmrig_57c0c6d7
{
	meta:
		author = "Elastic Security"
		id = "57c0c6d7-ded1-4a3e-9877-4003ab46d4a6"
		fingerprint = "b36ef33a052cdbda0db0048fc9da4ae4b4208c0fa944bc9322f029d4dfef35b8"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "100dc1ede4c0832a729d77725784d9deb358b3a768dfaf7ff9e96535f5b5a361"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrig"
		filetype = "executable"

	strings:
		$a = { 78 01 66 0F EF C9 49 89 38 0F BE 00 83 E8 30 F2 0F 2A C8 48 }

	condition:
		all of them
}
