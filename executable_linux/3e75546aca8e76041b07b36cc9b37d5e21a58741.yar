rule Linux_Exploit_CVE_2016_5195_b45098df
{
	meta:
		author = "Elastic Security"
		id = "b45098df-7f26-44a9-8078-f1c05d15cc38"
		fingerprint = "ed32e66f2c18b16a6f00d6a696a32cdb1b0b18413b4c1af059097f5d301ee084"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "e053aca86570b3781b3e08daab51382712270d2a375257c8b5789d3d87149314"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { FC 83 45 F8 01 81 7D F8 FF C1 EB 0B 7E D7 }

	condition:
		all of them
}
