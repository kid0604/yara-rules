rule Linux_Cryptominer_Xmrminer_d1a814b0
{
	meta:
		author = "Elastic Security"
		id = "d1a814b0-38a6-4469-a29b-75787f52d789"
		fingerprint = "1746bc1d96207bd1bb44e9ff248b76245feb76c1d965400c3abd3b9116ea8455"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer"
		filetype = "executable"

	strings:
		$a = { 01 48 8B 44 24 58 49 89 41 08 8B 01 48 C1 E0 05 4D 8D 04 07 48 8B 44 }

	condition:
		all of them
}
