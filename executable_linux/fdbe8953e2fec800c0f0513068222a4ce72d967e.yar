rule Linux_Trojan_Gafgyt_28a2fe0c
{
	meta:
		author = "Elastic Security"
		id = "28a2fe0c-eed5-4c79-81e6-3b11b73a4ebd"
		fingerprint = "a2c6beaec18ca876e8487c11bcc7a29279669588aacb7d3027d8d8df8f5bcead"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 28a2fe0c"
		filetype = "executable"

	strings:
		$a = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 2F 78 33 38 2F 78 46 4A 2F }

	condition:
		all of them
}
