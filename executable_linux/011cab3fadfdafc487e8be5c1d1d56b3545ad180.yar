rule Linux_Trojan_Rbot_366f1599
{
	meta:
		author = "Elastic Security"
		id = "366f1599-a287-44e6-bc2c-d835b2c2c024"
		fingerprint = "27166c9dab20d40c10a4f0ea5d0084be63fef48748395dd55c7a13ab6468e16d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Rbot"
		reference_sample = "5553d154a0e02e7f97415299eeae78e5bb0ecfbf5454e3933d6fd9675d78b3eb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Rbot 366f1599"
		filetype = "executable"

	strings:
		$a = { C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B }

	condition:
		all of them
}
