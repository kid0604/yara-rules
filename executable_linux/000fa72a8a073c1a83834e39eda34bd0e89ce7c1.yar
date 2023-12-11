rule Linux_Trojan_Mirai_aa39fb02
{
	meta:
		author = "Elastic Security"
		id = "aa39fb02-ca7e-4809-ab5d-00e92763f7ec"
		fingerprint = "b136ba6496816ba9737a3eb0e633c28a337511a97505f06e52f37b38599587cb"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 74 DE 8D 40 F1 3C 01 76 D7 80 FA 38 74 D2 80 FA 0A 74 CD 80 }

	condition:
		all of them
}
