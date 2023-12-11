rule Linux_Exploit_CVE_2017_16995_0c81a317
{
	meta:
		author = "Elastic Security"
		id = "0c81a317-b296-4cda-839c-a37903e86786"
		fingerprint = "40d192607a7237c41c35d90a48cbcfd95a79c0fe7c8017d41389f15a78d620f5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2017-16995"
		reference_sample = "48d927b4b18a03dfbce54bb5f4518869773737e449301ba2477eb797afbb9972"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit for CVE-2017-16995"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 48 89 7D F8 48 8B 45 F8 48 25 00 C0 FF FF 5D C3 55 48 }

	condition:
		all of them
}
