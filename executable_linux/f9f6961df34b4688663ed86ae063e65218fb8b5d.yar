rule Linux_Cryptominer_Xmrminer_504b42ca
{
	meta:
		author = "Elastic Security"
		id = "504b42ca-00a7-4917-8bb1-1957838a1d27"
		fingerprint = "265a3cb860e1f0ddafbe5658fa3a341d7419c89eecc350f8fc16e7a1e05a7673"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { D7 8B 04 8C 44 8D 50 FF 4C 89 04 C6 44 89 14 8C 75 D7 48 8B 2E 45 }

	condition:
		all of them
}
