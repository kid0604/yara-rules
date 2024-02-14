rule Linux_Hacktool_Lightning_d9a9173a
{
	meta:
		author = "Elastic Security"
		id = "d9a9173a-6372-4892-8913-77f5749aa045"
		fingerprint = "f6e9d662f22b6f08c5e6d32994d6ed933c6863870352dfb76e1540676663e7e0"
		creation_date = "2022-11-08"
		last_modified = "2024-02-13"
		threat_name = "Linux.Hacktool.Lightning"
		reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
		reference_sample = "48f9471c20316b295704e6f8feb2196dd619799edec5835734fc24051f45c5b7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Lightning"
		filetype = "executable"

	strings:
		$a1 = "cat /sys/class/net/%s/address" ascii fullword
		$a2 = "{\"ComputerName\":\"%s\",\"Guid\":\"%s\",\"RequestName\":\"%s\",\"Licence\":\"%s\"}" ascii fullword
		$a3 = "sleep 60 && ./%s &" ascii fullword
		$a4 = "Lightning.Core" ascii fullword

	condition:
		all of them
}
