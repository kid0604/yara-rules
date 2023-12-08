rule Windows_Trojan_Trickbot_d916ae65
{
	meta:
		author = "Elastic Security"
		id = "d916ae65-c97b-495c-89c2-4f1ec90081d2"
		fingerprint = "2e109ed59a1e759ef089e04c21016482bf70228da30d8b350fc370b4e4d120e0"
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
		$a = { 5F 24 01 10 CF 22 01 10 EC 22 01 10 38 23 01 10 79 23 01 10 82 }

	condition:
		all of them
}
