rule Linux_Hacktool_Portscan_e191222d
{
	meta:
		author = "Elastic Security"
		id = "e191222d-633a-4408-9a54-a70bb9e89cc0"
		fingerprint = "5580dd8b9180b8ff36c7d08a134b1b3782b41054d8b29b23fc5a79e7b0059fd1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Portscan"
		reference_sample = "e2f4313538c3ef23adbfc50f37451c318bfd1ffd0e5aaa346cce4cc37417f812"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Portscan"
		filetype = "executable"

	strings:
		$a = { 46 4F 55 4E 44 00 56 41 4C 55 45 00 44 45 4C 45 54 45 44 00 54 }

	condition:
		all of them
}
