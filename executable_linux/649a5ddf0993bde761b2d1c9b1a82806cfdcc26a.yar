rule Linux_Trojan_Rbot_96625c8c
{
	meta:
		author = "Elastic Security"
		id = "96625c8c-897c-4bf0-97e7-0dc04595cb94"
		fingerprint = "5dfabf693c87742ffa212573dded84a2c341628b79c7d11c16be493957c71a69"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Rbot"
		reference_sample = "a052cfad3034d851c6fad62cc8f9c65bceedc73f3e6a37c9befe52720fd0890e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Rbot"
		filetype = "executable"

	strings:
		$a = { 24 28 8B 45 3C 8B 54 05 78 01 EA 8B 4A 18 8B 5A 20 01 EB E3 38 49 8B }

	condition:
		all of them
}
