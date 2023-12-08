rule Linux_Trojan_Mobidash_e3086563
{
	meta:
		author = "Elastic Security"
		id = "e3086563-346d-43f1-89eb-42693dc17195"
		fingerprint = "8fc223f3850994479a70358da66fb31b610e00c9cbc3a94fd7323780383d738e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash"
		filetype = "executable"

	strings:
		$a = { 24 48 8B 4C 24 08 49 8B 55 00 48 39 D1 75 16 48 8D 64 24 10 }

	condition:
		all of them
}
