rule Linux_Trojan_Gafgyt_750fe002
{
	meta:
		author = "Elastic Security"
		id = "750fe002-cac1-4832-94d2-212aa5ec17e3"
		fingerprint = "f51347158a6477b0da4ed4df3374fbad92b6ac137aa4775f83035d1e30cba7dc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 750fe002"
		filetype = "executable"

	strings:
		$a = { 10 8B 45 0C 40 8A 00 3C FC 75 06 C6 45 FF FE EB 50 8B 45 0C 40 }

	condition:
		all of them
}
