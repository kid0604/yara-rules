rule Linux_Exploit_CVE_2010_3301_d0eb0924
{
	meta:
		author = "Elastic Security"
		id = "d0eb0924-dae1-46f9-a4d0-c9e69f781a22"
		fingerprint = "bb288a990938aa21aba087a0400d6f4765a622f8ed36d1dd7953d09cbb09ff83"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2010-3301"
		reference_sample = "907995e90a80d3ace862f2ffdf13fd361762b5acc5397e14135d85ca6a61619b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux exploit for CVE-2010-3301"
		filetype = "executable"

	strings:
		$a = { E8 3C FA FF FF 83 7D EC FF 75 19 BF 20 13 40 00 }

	condition:
		all of them
}
