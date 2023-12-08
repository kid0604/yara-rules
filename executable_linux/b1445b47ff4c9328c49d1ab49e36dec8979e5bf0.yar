rule Linux_Trojan_Gafgyt_30444846
{
	meta:
		author = "Elastic Security"
		id = "30444846-439f-41e1-b0b4-c12da774a228"
		fingerprint = "3c74db508de7c8c1c190d5569e0a2c2b806f72045e7b74d44bfbaed20ecb956b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "c84b81d79d437bb9b8a6bad3646aef646f2a8e1f1554501139648d2f9de561da"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 64 20 2B 78 20 74 66 74 70 31 2E 73 68 3B 20 73 68 20 74 66 74 }

	condition:
		all of them
}
