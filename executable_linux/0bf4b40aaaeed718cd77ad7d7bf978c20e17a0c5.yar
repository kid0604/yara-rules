rule Linux_Trojan_Mirai_0d73971c
{
	meta:
		author = "Elastic Security"
		id = "0d73971c-4253-4e7d-b1e1-20b031197f9e"
		fingerprint = "95279bc45936ca867efb30040354c8ff81de31dccda051cfd40b4fb268c228c5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 0d73971c"
		filetype = "executable"

	strings:
		$a = { 89 C2 83 EB 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 31 F0 C1 }

	condition:
		all of them
}
