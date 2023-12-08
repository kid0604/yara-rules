rule Linux_Trojan_Mirai_93fc3657
{
	meta:
		author = "Elastic Security"
		id = "93fc3657-fd21-4e93-a728-c084fc0a6a4a"
		fingerprint = "d01a9e85a01fad913ca048b60bda1e5a2762f534e5308132c1d3098ac3f561ee"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 93fc3657"
		filetype = "executable"

	strings:
		$a = { 00 00 00 89 44 24 60 89 D1 31 C0 8B 7C 24 28 FC F3 AB 89 D1 8B 7C }

	condition:
		all of them
}
