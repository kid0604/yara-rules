rule Linux_Trojan_Gafgyt_0cd591cd
{
	meta:
		author = "Elastic Security"
		id = "0cd591cd-c348-4c3a-a895-2063cf892cda"
		fingerprint = "96c4ff70729ddb981adafd8c8277649a88a87e380d2f321dff53f0741675fb1b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt with ID 0cd591cd"
		filetype = "executable"

	strings:
		$a = { 4E F8 48 8D 4E D8 49 8D 42 E0 48 83 C7 03 EB 6B 4C 8B 46 F8 48 8D }

	condition:
		all of them
}
