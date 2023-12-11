rule Windows_Trojan_RedLineStealer_f54632eb
{
	meta:
		author = "Elastic Security"
		id = "f54632eb-2c66-4aff-802d-ad1c076e5a5e"
		fingerprint = "6a9d45969c4d58181fca50d58647511b68c1e6ee1eeac2a1838292529505a6a0"
		creation_date = "2021-06-12"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "d82ad08ebf2c6fac951aaa6d96bdb481aa4eab3cd725ea6358b39b1045789a25"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Yara rule for detecting Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a1 = "ttp://checkip.amazonaws.com/logins.json" wide fullword
		$a2 = "https://ipinfo.io/ip%appdata%\\" wide fullword
		$a3 = "Software\\Valve\\SteamLogin Data" wide fullword
		$a4 = "get_ScannedWallets" ascii fullword
		$a5 = "get_ScanTelegram" ascii fullword
		$a6 = "get_ScanGeckoBrowsersPaths" ascii fullword
		$a7 = "<Processes>k__BackingField" ascii fullword
		$a8 = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii fullword
		$a9 = "<ScanFTP>k__BackingField" ascii fullword
		$a10 = "DataManager.Data.Credentials" ascii fullword

	condition:
		6 of ($a*)
}
