rule Linux_Trojan_Mirai_122ff2e6
{
	meta:
		author = "Elastic Security"
		id = "122ff2e6-56e6-4aa8-a3ec-c19d31eb1f80"
		fingerprint = "3c9ffd7537e30a21eefa6c174f801264b92a85a1bc73e34e6dc9e29f84658348"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "c7dd999a033fa3edc1936785b87cd69ce2f5cac5a084ddfaf527a1094e718bc4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 122ff2e6"
		filetype = "executable"

	strings:
		$a = { 24 EB 15 89 F0 83 C8 01 EB 03 8B 5B 08 3B 43 04 72 F8 8B 4B 0C 89 }

	condition:
		all of them
}
