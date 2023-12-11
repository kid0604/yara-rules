rule Linux_Exploit_CVE_2016_5195_9c67a994
{
	meta:
		author = "Elastic Security"
		id = "9c67a994-dabf-4cb7-95d7-4cc47402be28"
		fingerprint = "fc6690eef99dd9f84f62444d7a7e1b52dc7f46e831a5ab3e87d4282bba979fde"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "70429d67402a43ed801e295b1ae1757e4fccd5d786c09ee054591ae51dfc1b25"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux kernel exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { FC 83 45 F8 01 81 7D F8 FF C1 EB 0B 7E ?? 8B }

	condition:
		all of them
}
