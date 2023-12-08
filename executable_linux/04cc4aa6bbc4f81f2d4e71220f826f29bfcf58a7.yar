rule Linux_Trojan_Mirai_7146e518
{
	meta:
		author = "Elastic Security"
		id = "7146e518-f6f4-425d-bac8-b31edc0ac559"
		fingerprint = "334ef623a8dadd33594e86caca1c95db060361c65bf366bacb9bc3d93ba90c4f"
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
		$a = { 85 82 11 79 AF 20 C2 7A 9E 18 6C A9 00 21 E2 6A C6 D5 59 B4 E8 }

	condition:
		all of them
}
