rule Linux_Trojan_Mirai_1754b331
{
	meta:
		author = "Elastic Security"
		id = "1754b331-5704-43c1-91be-89c7a0dd29a4"
		fingerprint = "35db945d116a4c9264af44a9947a5e831ea655044728dc78770085c7959a678e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "0d89fc59d0de2584af0e4614a1561d1d343faa766edfef27d1ea96790ac7014b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 1754b331"
		filetype = "executable"

	strings:
		$a = { CF 07 66 5F 10 F0 EB 0C 42 0B 2F 0B 0B 43 C1 42 E4 C2 7C 85 }

	condition:
		all of them
}
