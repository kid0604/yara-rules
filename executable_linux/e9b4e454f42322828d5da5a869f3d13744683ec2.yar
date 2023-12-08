rule Linux_Trojan_Tsunami_6b3974b2
{
	meta:
		author = "Elastic Security"
		id = "6b3974b2-fd7f-4ebf-8aba-217761e7b846"
		fingerprint = "942a35f7acacf1d07577fe159a34dc7b04e5d07ff32ea13be975cfeea23e34be"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "2216776ba5c6495d86a13f6a3ce61b655b72a328ca05b3678d1abb7a20829d04"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami variant"
		filetype = "executable"

	strings:
		$a = { F4 89 45 EC 8B 45 EC C9 C3 55 89 E5 57 83 EC 0C EB 1F 8B 45 08 B9 FF FF }

	condition:
		all of them
}
