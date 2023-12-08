rule Linux_Trojan_Gafgyt_ea92cca8
{
	meta:
		author = "Elastic Security"
		id = "ea92cca8-bba7-4a1c-9b88-a2d051ad0021"
		fingerprint = "aa4aee9f3d6bedd8234eaf8778895a0f5d71c42b21f2a428f01f121e85704e8e"
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
		$a = { 53 65 6C 66 20 52 65 70 20 46 75 63 6B 69 6E 67 20 4E 65 54 69 53 20 61 6E 64 }

	condition:
		all of them
}
