rule Windows_Hacktool_WinPEAS_ng_b6bb3e7c
{
	meta:
		author = "Elastic Security"
		id = "b6bb3e7c-29f6-4bc6-8082-558a56512fc3"
		fingerprint = "ecc2217349244cd78fa5be040653c02096ee8b6a2f2691309fd7f9f62612fa79"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, Windows credentials module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "Windows Credentials" ascii wide
		$win_1 = "Checking Windows Vault" ascii wide
		$win_2 = "Identity.*|Credential.*|Resource.*" ascii wide
		$win_3 = "Checking Credential manager" ascii wide
		$win_4 = "Saved RDP connections" ascii wide
		$win_5 = "Recently run commands" ascii wide
		$win_6 = "Checking for DPAPI" ascii wide
		$win_7 = "Checking for RDCMan" ascii wide
		$win_8 = "Looking for saved Wifi credentials" ascii wide
		$win_9 = "Looking AppCmd.exe" ascii wide

	condition:
		5 of them
}
