rule Windows_Trojan_Netwire_f85e4abc
{
	meta:
		author = "Elastic Security"
		id = "f85e4abc-f2d7-491b-a1ad-a59f287e5929"
		fingerprint = "66cae88c9f8b975133d2b3af94a869244d273021261815b15085c638352bf2ca"
		creation_date = "2022-08-14"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Netwire"
		reference_sample = "ab037c87d8072c63dc22b22ff9cfcd9b4837c1fee2f7391d594776a6ac8f6776"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Netwire"
		filetype = "executable"

	strings:
		$a = { C9 0F 44 C8 D0 EB 8A 44 24 12 0F B7 C9 75 D1 32 C0 B3 01 8B CE 88 44 }

	condition:
		all of them
}
