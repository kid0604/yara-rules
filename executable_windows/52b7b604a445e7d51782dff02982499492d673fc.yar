rule Windows_Trojan_Trickbot_d2110921
{
	meta:
		author = "Elastic Security"
		id = "d2110921-b957-49b7-8a26-4c0b7d1d58ad"
		fingerprint = "55dbbcbc77ec51a378ad2ba8d56cb0811d23b121cacd037503fd75d08529c5b5"
		creation_date = "2021-03-29"
		last_modified = "2021-08-23"
		description = "Targets shareDll64.dll module containing functionality use to spread Trickbot across local networks"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "05EF40F7745DB836DE735AC73D6101406E1D9E58C6B5F5322254EB75B98D236A"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "module64.dll" ascii fullword
		$a2 = "Size - %d kB" ascii fullword
		$a3 = "%s - FAIL" wide fullword
		$a4 = "%s - SUCCESS" wide fullword
		$a5 = "ControlSystemInfoService" ascii fullword
		$a6 = "<moduleconfig><autostart>yes</autostart></moduleconfig>" ascii fullword
		$a7 = "Copy: %d" wide fullword
		$a8 = "Start sc 0x%x" wide fullword
		$a9 = "Create sc 0x%x" wide fullword
		$a10 = "Open sc %d" wide fullword
		$a11 = "ServiceInfoControl" ascii fullword

	condition:
		3 of ($a*)
}
