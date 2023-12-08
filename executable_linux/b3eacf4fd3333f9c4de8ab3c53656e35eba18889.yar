rule Linux_Trojan_Mirai_22965a6d
{
	meta:
		author = "Elastic Security"
		id = "22965a6d-85d3-4f7c-be4a-581044581b77"
		fingerprint = "a34bcba23cde4a2a49ef8192fa2283ce03c75b2d1d08f1fea477932d4b9f5135"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "09c821aa8977f67878f8769f717c792d69436a951bb5ac06ce5052f46da80a48"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 22965a6d"
		filetype = "executable"

	strings:
		$a = { E6 4A 64 2B E4 82 D1 E3 F6 5E 88 34 DA 36 30 CE 4E 83 EC F1 }

	condition:
		all of them
}
