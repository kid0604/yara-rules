rule Linux_Trojan_Mirai_5c62e6b2
{
	meta:
		author = "Elastic Security"
		id = "5c62e6b2-9f6a-4c6d-b3fc-c6cbc8cf0b4b"
		fingerprint = "39501003c45c89d6a08f71fbf9c442bcc952afc5f1a1eb7b5af2d4b7633698a8"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai based on specific fingerprint"
		filetype = "executable"

	strings:
		$a = { FF C1 83 F9 05 7F 14 48 63 C1 48 89 94 C4 00 01 00 00 FF C6 48 }

	condition:
		all of them
}
