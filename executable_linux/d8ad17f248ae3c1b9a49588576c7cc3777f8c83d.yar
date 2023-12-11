rule Linux_Exploit_CVE_2016_5195_364f3b7b
{
	meta:
		author = "Elastic Security"
		id = "364f3b7b-4361-44ca-bf49-e26c123ae4bd"
		fingerprint = "ec6cf1d090cd57434c4d3c1c3511fd4b683ff109bfd0ce859552d58cbb83984a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "0d4c43bf0cdd6486a4bcab988517e58b8c15d276f41600e596ecc28b0b728e69"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux kernel exploit for CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 9C 01 7E 24 48 8B 45 90 48 8B 40 08 48 89 45 F8 48 8B 45 F8 48 }

	condition:
		all of them
}
