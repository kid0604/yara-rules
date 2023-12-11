rule Linux_Cryptominer_Xmrig_79b42b21
{
	meta:
		author = "Elastic Security"
		id = "79b42b21-1408-4837-8f1f-6de30d7f5777"
		fingerprint = "4cd0481edd1263accdac3ff941df4e31ef748bded0fba5fe55a9cffa8a37b372"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrig malware"
		filetype = "executable"

	strings:
		$a = { FC 00 79 0A 8B 45 B8 83 E0 04 85 C0 75 38 8B 45 EC 83 C0 01 }

	condition:
		all of them
}
