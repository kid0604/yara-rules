rule Linux_Trojan_Rekoobe_1d307d7c
{
	meta:
		author = "Elastic Security"
		id = "1d307d7c-cc84-44e5-8fa0-eda9fffb3964"
		fingerprint = "11b1474dbdc376830bca50dbeea7f7f786c8a9b2ac51a139c4e06bed7c867121"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Rekoobe"
		reference_sample = "00bc669f79b2903c5d9e6412050655486111647c646698f9a789e481a7c98662"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Rekoobe (1d307d7c)"
		filetype = "executable"

	strings:
		$a = { F8 01 75 56 83 7C 24 3C 10 75 1C BE ?? ?? 60 00 }

	condition:
		all of them
}
