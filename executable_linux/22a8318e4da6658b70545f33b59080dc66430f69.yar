rule Linux_Exploit_CVE_2016_5195_2fa988e3
{
	meta:
		author = "Elastic Security"
		id = "2fa988e3-dfaf-44c8-bfaa-889778858e22"
		fingerprint = "a841f4b929c79eadfa8deeb3a6f410056aec94dd1e0d9c8e5dc31675de936403"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "679392e78d4abefc05b885e43aaccc2da235bd7f2a267c6ecfbe2cf824776993"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 48 83 EC 20 89 7D EC 89 75 E8 8B 45 E8 48 C1 E0 05 48 }

	condition:
		all of them
}
