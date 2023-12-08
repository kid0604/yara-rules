rule Linux_Exploit_CVE_2016_5195_ffa7f059
{
	meta:
		author = "Elastic Security"
		id = "ffa7f059-b825-4dd6-b10d-e57549a2704f"
		fingerprint = "c451689042d9290d1bb5b931e002237584217bbddfc0d96c2486a61cb5c37d31"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "a073c6be047ea7b4500b1ffdc8bdadd9a06f9efccd38c88e0fc976b97b2b2df5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { F8 83 45 FC 01 81 7D FC FF C1 EB 0B 7E D7 }

	condition:
		all of them
}
