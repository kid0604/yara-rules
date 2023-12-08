rule Linux_Exploit_Lotoor_03c81bd9
{
	meta:
		author = "Elastic Security"
		id = "03c81bd9-c7d1-4044-9cce-951637b2b523"
		fingerprint = "329dc1e21088c87095ee030c597a3340f838c338403ae64aec574e0086281461"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "3fc701a2caab0297112501f55eaeb05264c5e4099c411dcadc7095627e19837a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 65 00 65 78 70 5F 73 74 61 74 65 00 6D 65 6D 73 65 74 00 70 }

	condition:
		all of them
}
