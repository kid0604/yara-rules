rule Linux_Exploit_CVE_2016_4557_b7e15f5e
{
	meta:
		author = "Elastic Security"
		id = "b7e15f5e-73d2-4718-8fac-e6a285b0c73c"
		fingerprint = "14baf456521fd7357a70ddde9da11f27d17a45d7d12c70a0101d6bdc45e30c74"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Exploit.CVE-2016-4557"
		reference_sample = "bbed2f81104b5eb4a8475deff73b29a350dc8b0f96dcc4987d0112b993675271"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-4557"
		filetype = "executable"

	strings:
		$a = { 2E 20 69 66 20 74 68 69 73 20 77 6F 72 6B 65 64 2C 20 79 6F }

	condition:
		all of them
}
