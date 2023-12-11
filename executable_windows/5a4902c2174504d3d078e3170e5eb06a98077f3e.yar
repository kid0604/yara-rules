rule Windows_Trojan_RedLineStealer_3d9371fd
{
	meta:
		author = "Elastic Security"
		id = "3d9371fd-c094-40fc-baf8-f0e9e9a54ff9"
		fingerprint = "2d7ff7894b267ba37a2d376b022bae45c4948ef3a70b1af986e7492949b5ae23"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "0ec522dfd9307772bf8b600a8b91fd6facd0bf4090c2b386afd20e955b25206a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a1 = "get_encrypted_key" ascii fullword
		$a2 = "get_PassedPaths" ascii fullword
		$a3 = "ChromeGetLocalName" ascii fullword
		$a4 = "GetBrowsers" ascii fullword
		$a5 = "Software\\Valve\\SteamLogin Data" wide fullword
		$a6 = "%appdata%\\" wide fullword
		$a7 = "ScanPasswords" ascii fullword

	condition:
		all of them
}
