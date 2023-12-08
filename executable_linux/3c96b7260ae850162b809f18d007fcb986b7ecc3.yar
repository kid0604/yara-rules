rule Linux_Trojan_Gafgyt_94a44aa5
{
	meta:
		author = "Elastic Security"
		id = "94a44aa5-6c8b-40b9-8aac-d18cf4a76a19"
		fingerprint = "daf7e0382dd4a566eb5a4aac8c5d9defd208f332d8e327637d47b50b9ef271f9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "a7694202f9c32a9d73a571a30a9e4a431d5dfd7032a500084756ba9a48055dba"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 94a44aa5"
		filetype = "executable"

	strings:
		$a = { 00 00 00 83 F8 FF 0F 45 C2 48 8B 4C 24 08 64 48 33 0C 25 28 00 }

	condition:
		all of them
}
