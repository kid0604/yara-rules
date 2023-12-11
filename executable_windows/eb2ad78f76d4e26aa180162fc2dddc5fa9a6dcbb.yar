rule Windows_Trojan_SuddenIcon_ac021ae0
{
	meta:
		author = "Elastic Security"
		id = "ac021ae0-67c6-45cf-a467-eb3c2b84b3e4"
		fingerprint = "115d4fc78bae7b5189a94b82ffd6547dfe89cfb66bf59d0e1d77c10fb937d2f7"
		creation_date = "2023-03-30"
		last_modified = "2023-03-30"
		threat_name = "Windows.Trojan.SuddenIcon"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan SuddenIcon"
		filetype = "executable"

	strings:
		$str1 = "%s\\%s\\%s\\%s" wide fullword
		$str2 = "%s.old" wide fullword
		$str3 = "\n******************************** %s ******************************\n\n" wide fullword
		$str4 = "HostName: %s\\r\\nDomainName: %s\\r\\nOsVersion: %d.%d.%d\\r\\n\\r\\n" wide fullword
		$str5 = "%s\\r\\nDomainName: %s\\r\\nOsVersion: %d.%d.%d\\r\\n\\r\\n" wide fullword
		$str6 = "AppData\\Local\\Google\\Chrome\\User Data" wide fullword
		$str7 = "SELECT url, title FROM urls ORDER BY id DESC LIMIT 500" wide fullword
		$str8 = "SELECT url, title FROM moz_places ORDER BY id DESC LIMIT 500" wide fullword
		$b1 = "\\3CXDesktopApp\\config.json" wide fullword

	condition:
		6 of ($str*) or 1 of ($b*)
}
