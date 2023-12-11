rule Linux_Trojan_Gafgyt_fa19b8fc
{
	meta:
		author = "Elastic Security"
		id = "fa19b8fc-6035-4415-842f-4993411ab43e"
		fingerprint = "4f213d5d1b4a0b832ed7a6fac91bef7c29117259b775b85409e9e4c8aec2ad10"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "a7cfc16ec33ec633cbdcbff3c4cefeed84d7cbe9ca1f4e2a3b3e43d39291cd6b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint fa19b8fc"
		filetype = "executable"

	strings:
		$a = { 02 63 10 01 0F 4B 85 14 36 B0 60 53 03 4F 0D B2 05 76 02 B7 00 00 }

	condition:
		all of them
}
