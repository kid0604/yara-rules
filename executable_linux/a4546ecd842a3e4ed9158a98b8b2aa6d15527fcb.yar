rule Linux_Trojan_Gafgyt_9abf7e0c
{
	meta:
		author = "Elastic Security"
		id = "9abf7e0c-5076-4881-a488-f0f62810f843"
		fingerprint = "7d02513aaef250091a58db58435a1381974e55c2ed695c194b6b7b83c235f848"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt with ID 9abf7e0c"
		filetype = "executable"

	strings:
		$a = { 55 E0 0F B6 42 0D 83 C8 01 88 42 0D 48 8B 55 E0 0F B6 42 0D 83 }

	condition:
		all of them
}
