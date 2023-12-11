rule Linux_Trojan_Mirai_da4aa3b3
{
	meta:
		author = "Elastic Security"
		id = "da4aa3b3-521d-4fde-b1be-c381d28c701c"
		fingerprint = "8b004abc37f47de6e4ed35284c23db0f6617eec037a71ce92c10aa8efc3bdca5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "dbc246032d432318f23a4c1e5b6fcd787df29da3bf418613f588f758dcd80617"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant da4aa3b3"
		filetype = "executable"

	strings:
		$a = { 01 D0 C1 E0 03 89 C2 8B 45 A0 01 D0 0F B6 40 14 3C 1F 77 65 8B }

	condition:
		all of them
}
