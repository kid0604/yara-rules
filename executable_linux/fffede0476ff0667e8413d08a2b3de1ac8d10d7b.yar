rule Linux_Trojan_Mirai_a3cedc45
{
	meta:
		author = "Elastic Security"
		id = "a3cedc45-962d-44b5-bf0e-67166fa6c1a4"
		fingerprint = "8335e540adfeacdf8f45c9cb36b08fea7a06017bb69aa264dc29647e7ca4a541"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 74 2C 48 8B 03 48 83 E0 FE 48 29 C3 48 8B 43 08 48 83 E0 FE 4A 8D }

	condition:
		all of them
}
