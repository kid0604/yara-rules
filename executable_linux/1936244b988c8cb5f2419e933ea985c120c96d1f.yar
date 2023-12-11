rule Linux_Exploit_CVE_2017_100011_21025f50
{
	meta:
		author = "Elastic Security"
		id = "21025f50-93af-4ea7-bdcb-ab4e210b8ac6"
		fingerprint = "a50c81daf4f081d7ddf61d05ab64d8fada5c4d6cdf8d28eb30c689e868d905aa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2017-100011"
		reference_sample = "32db88b2c964ce48e6d1397ca655075ea54ce298340af55ea890a2411a67d554"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2017-100011"
		filetype = "executable"

	strings:
		$a = { 5D 20 64 6F 6E 65 2C 20 6B 65 72 6E 65 6C 20 74 65 78 74 3A }

	condition:
		all of them
}
