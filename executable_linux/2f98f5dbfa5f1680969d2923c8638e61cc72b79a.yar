rule Linux_Exploit_CVE_2016_5195_fb24c7e4
{
	meta:
		author = "Elastic Security"
		id = "fb24c7e4-db4f-405e-8e88-bc313b9a0358"
		fingerprint = "0a5f15ddb425a6e00f6c3964b4dbdc91a856fd06b6e45dfd4fded8ed97f21ae8"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "a073c6be047ea7b4500b1ffdc8bdadd9a06f9efccd38c88e0fc976b97b2b2df5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux kernel exploit for CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { F8 83 45 FC 01 81 7D FC FF C1 EB 0B 7E ?? 8B 45 }

	condition:
		all of them
}
