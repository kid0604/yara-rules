rule Linux_Trojan_Gafgyt_0e03b7d3
{
	meta:
		author = "Elastic Security"
		id = "0e03b7d3-a6b0-46a0-920e-c15ee7e723f7"
		fingerprint = "1bf1f271005328669b3eb4940e2b75eff9fc47208d79a12196fd7ce04bc4dbe8"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant 0e03b7d3"
		filetype = "executable"

	strings:
		$a = { F5 74 84 32 63 29 5A B2 78 FF F7 FA 0E 51 B3 2F CD 7F 10 FA }

	condition:
		all of them
}
