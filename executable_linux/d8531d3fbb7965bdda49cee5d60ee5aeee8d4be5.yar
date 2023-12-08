rule Linux_Cryptominer_Generic_0d6005a1
{
	meta:
		author = "Elastic Security"
		id = "0d6005a1-a481-4679-a214-f1e3ef8bf1d0"
		fingerprint = "435040ec452d337c60435b07622d3a8af8e3b7e8eb6ec2791da6aae504cc2266"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "230d46b39b036552e8ca6525a0d2f7faadbf4246cdb5e0ac9a8569584ef295d4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 79 73 00 6E 6F 5F 6D 6C 63 6B 00 77 61 72 6E 00 6E 65 76 65 }

	condition:
		all of them
}
