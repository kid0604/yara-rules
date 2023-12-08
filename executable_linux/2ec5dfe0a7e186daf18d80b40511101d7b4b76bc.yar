rule Linux_Trojan_Mirai_1538ce1a
{
	meta:
		author = "Elastic Security"
		id = "1538ce1a-7078-4be3-bd69-7e692a1237f5"
		fingerprint = "f3d82cae74db83b7a49c5ec04d1a95c3b17ab1b935de24ca5c34e9b99db36803"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 1538ce1a"
		filetype = "executable"

	strings:
		$a = { FD 00 00 00 FD 34 FD FD 04 40 FD 04 FD FD 7E 14 FD 78 14 1F 0F }

	condition:
		all of them
}
