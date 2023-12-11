rule Linux_Exploit_Lotoor_bb384bc9
{
	meta:
		author = "Elastic Security"
		id = "bb384bc9-fcda-4ad4-82ad-b95de750d31c"
		fingerprint = "6878670c1fa154f5c4a845a824c63d0a900359b6e122b3fa759077c6a7e33e4c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "ecc6635117b99419255af5d292a7af3887b06d5f3b0f59d158281eebfe606445"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux.Exploit.Lotoor is a Linux exploit that targets the x86 architecture and can be found in files and memory."
		filetype = "executable"

	strings:
		$a = { C2 75 64 4C 8B 45 F0 49 83 C0 04 4C 8B 4D F0 49 83 C1 08 48 8B }

	condition:
		all of them
}
