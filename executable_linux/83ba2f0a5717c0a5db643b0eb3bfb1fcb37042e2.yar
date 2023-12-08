rule Linux_Exploit_CVE_2010_3301_a5828970
{
	meta:
		author = "Elastic Security"
		id = "a5828970-7a30-421c-be92-5659c18b88d1"
		fingerprint = "72223f502b2a129380ab011b785f6589986d2eb177580339755d12840617ce5f"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2010-3301"
		reference_sample = "4fc781f765a65b714ec27080f25c03f20e06830216506e06325240068ba62d83"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2010-3301"
		filetype = "executable"

	strings:
		$a = { E8 7C FC FF FF 83 7D EC FF 75 19 BF 40 0E 40 00 }

	condition:
		all of them
}
