rule Windows_Trojan_XWorm_b7d6eaa8
{
	meta:
		author = "Elastic Security"
		id = "b7d6eaa8-f4e6-42e6-95b2-ce67f513d6c5"
		fingerprint = "0c68cb5c8425cccc6af66c33a14e14e5f16d91835209bd38cddf38fad07a40fa"
		creation_date = "2024-09-10"
		last_modified = "2024-10-15"
		threat_name = "Windows.Trojan.XWorm"
		reference_sample = "6fc4ff3f025545f7e092408b035066c1138253b972a2e9ef178e871d36f03acd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan XWorm"
		filetype = "executable"

	strings:
		$str1 = "XWorm V" wide
		$str2 = "XLogger" ascii fullword
		$str3 = "<Xwormmm>" wide fullword
		$str4 = "ActivatePong" ascii fullword
		$str5 = "ReportWindow" ascii fullword
		$str6 = "ConnectServer" ascii fullword

	condition:
		4 of them
}
