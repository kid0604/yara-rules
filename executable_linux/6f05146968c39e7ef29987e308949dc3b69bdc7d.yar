rule Linux_Trojan_Mirai_637f2c04
{
	meta:
		author = "Elastic Security"
		id = "637f2c04-98e4-45aa-b60a-14a96c6cebb7"
		fingerprint = "7af3d573af8b7f8252590a53adda52ecf53bdaf9a86b52ef50702f048e08ba8c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 637f2c04"
		filetype = "executable"

	strings:
		$a = { 10 48 8B 45 E0 0F B6 00 38 C2 0F 95 C0 48 FF 45 E8 48 FF 45 E0 }

	condition:
		all of them
}
