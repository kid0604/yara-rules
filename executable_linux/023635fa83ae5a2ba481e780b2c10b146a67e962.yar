rule Linux_Trojan_Mirai_520deeb8
{
	meta:
		author = "Elastic Security"
		id = "520deeb8-cbc0-4225-8d23-adba5e040471"
		fingerprint = "f4dfd1d76e07ff875eedfe0ef4f861bee1e4d8e66d68385f602f29cc35e30cca"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 520deeb8"
		filetype = "executable"

	strings:
		$a = { ED 48 89 44 24 30 44 89 6C 24 10 7E 47 48 89 C1 44 89 E8 44 }

	condition:
		all of them
}
