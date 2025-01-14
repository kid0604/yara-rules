rule Windows_Trojan_Vidar_65d3d7e5
{
	meta:
		author = "Elastic Security"
		id = "65d3d7e5-2a5f-4434-8578-6ccaa4528086"
		fingerprint = "249ba1f0078792d3b4cb61b6c7e902b327305a1398a3c88f1720ad8e6c30fe57"
		creation_date = "2024-10-14"
		last_modified = "2024-10-24"
		threat_name = "Windows.Trojan.Vidar"
		reference_sample = "83d7c2b437a5cbb314c457d3b7737305dadb2bc02d6562a98a8a8994061fe929"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Vidar with specific strings"
		filetype = "executable"

	strings:
		$str_1 = "avghooka.dll" wide fullword
		$str_2 = "api_log.dll" wide fullword
		$str_3 = "babyfox.dll" ascii fullword
		$str_4 = "vksaver.dll" ascii fullword
		$str_5 = "delays.tmp" wide fullword
		$str_6 = "\\Monero\\wallet.keys" ascii fullword
		$str_7 = "wallet_path" ascii fullword
		$str_8 = "Hong Lee" ascii fullword
		$str_9 = "milozs" ascii fullword

	condition:
		6 of them
}
