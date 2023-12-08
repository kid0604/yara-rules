rule Linux_Trojan_Gafgyt_ae01d978
{
	meta:
		author = "Elastic Security"
		id = "ae01d978-d07d-4813-a22b-5d172c477d08"
		fingerprint = "2d937c6009cfd53e11af52482a7418546ae87b047deabcebf3759e257cd89ce1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 00 00 2C 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }

	condition:
		all of them
}
