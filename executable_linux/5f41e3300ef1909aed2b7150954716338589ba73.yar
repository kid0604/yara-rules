rule Linux_Trojan_Mirai_82c361d4
{
	meta:
		author = "Elastic Security"
		id = "82c361d4-2adf-48f2-a9be-677676d7451f"
		fingerprint = "a8a4252c6f7006181bdb328d496e0e29522f87e55229147bc6cf4d496f5828fb"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "f8dbcf0fc52f0c717c8680cb5171a8c6c395f14fd40a2af75efc9ba5684a5b49"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 82c361d4"
		filetype = "executable"

	strings:
		$a = { 23 CB 67 4C 94 11 6E 75 EC A6 76 98 23 CC 80 CF AE 3E A6 0C }

	condition:
		all of them
}
