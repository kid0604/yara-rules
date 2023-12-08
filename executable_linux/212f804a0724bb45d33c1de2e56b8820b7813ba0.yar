rule Linux_Exploit_CVE_2012_0056_06b2dff5
{
	meta:
		author = "Elastic Security"
		id = "06b2dff5-250a-46e0-b763-8e6b04498fe2"
		fingerprint = "82b200deae93c8fa376d670f5091d9a63730a6f5b5e8a0567fe9c283075d57c0"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2012-0056"
		reference_sample = "168b3fb1c675ab76224c641e228434495160502a738b64172c679e8ce791ac17"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2012-0056"
		filetype = "executable"

	strings:
		$a = { 20 66 64 20 69 6E 20 70 61 72 65 6E 74 2E 00 5B 2B 5D 20 52 65 63 }

	condition:
		all of them
}
