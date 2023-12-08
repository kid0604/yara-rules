rule Linux_Trojan_Rekoobe_7f7aba78
{
	meta:
		author = "Elastic Security"
		id = "7f7aba78-6e64-41c4-a542-088a8270a941"
		fingerprint = "acb8f0fb7a7b0c5329afeadb70fc46ab72a7704cdeef64e7575fbf2c2dd3dbe2"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Rekoobe"
		reference_sample = "50b73742726b0b7e00856e288e758412c74371ea2f0eaf75b957d73dfb396fd7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Rekoobe"
		filetype = "executable"

	strings:
		$a = { F0 89 D0 31 D8 21 F0 31 D8 03 45 F0 89 CF C1 CF 1B 01 F8 C1 }

	condition:
		all of them
}
