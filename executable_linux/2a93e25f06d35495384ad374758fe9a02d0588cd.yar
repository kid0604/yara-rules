rule Linux_Trojan_Mirai_07b1f4f6
{
	meta:
		author = "Elastic Security"
		id = "07b1f4f6-9324-48ab-9086-b738fdaf47c3"
		fingerprint = "bebafc3c8e68b36c04dc9af630b81f9d56939818d448759fdd83067e4c97e87a"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 07b1f4f6"
		filetype = "executable"

	strings:
		$a = { FD 08 FD 5C 24 48 66 FD 07 66 FD 44 24 2E 66 FD FD 08 66 FD 47 }

	condition:
		all of them
}
