rule Linux_Trojan_Rekoobe_52462fe8
{
	meta:
		author = "Elastic Security"
		id = "52462fe8-a40c-4620-b539-d0c1f9d2ceee"
		fingerprint = "e09e8e023b3142610844bf7783c5472a32f63c77f9a46edc028e860da63e6eeb"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Rekoobe"
		reference_sample = "c1d8c64105caecbd90c6e19cf89301a4dc091c44ab108e780bdc8791a94caaad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Rekoobe"
		filetype = "executable"

	strings:
		$a = { 1C D8 48 8B 5A E8 4A 33 0C DE 48 89 4A E0 89 D9 C1 E9 18 48 8B }

	condition:
		all of them
}
