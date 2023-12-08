rule Linux_Trojan_Generic_402be6c5
{
	meta:
		author = "Elastic Security"
		id = "402be6c5-a1d8-4d7a-88ba-b852e0db1098"
		fingerprint = "1e906f5a06f688084edf537ead0b7e887bd9e0fcc39990c976ea8c136dc52624"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "d30a8f5971763831f92d9a6dd4720f52a1638054672a74fdb59357ae1c9e6deb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic 402be6c5"
		filetype = "executable"

	strings:
		$a = { C0 52 4C 95 42 11 01 64 E9 D7 39 E4 89 34 FA 48 01 02 C1 3B 39 }

	condition:
		all of them
}
