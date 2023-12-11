rule Windows_Trojan_Trickbot_cb95dc06
{
	meta:
		author = "Elastic Security"
		id = "cb95dc06-6383-4487-bf10-7fd68d61e37a"
		fingerprint = "0d28f570db007a1b91fe48aba18be7541531cceb7f11a6a4471e92abd55b3b90"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot"
		filetype = "executable"

	strings:
		$a = { 08 5F 5E 33 C0 5B 5D C3 8B 55 14 89 02 8B 45 18 5F 89 30 B9 01 00 }

	condition:
		all of them
}
