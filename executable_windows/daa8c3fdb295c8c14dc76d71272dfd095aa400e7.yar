rule Windows_Hacktool_WinPEAS_ng_57587f8c
{
	meta:
		author = "Elastic Security"
		id = "57587f8c-8fc6-41cc-bcb3-3d1d77c74222"
		fingerprint = "9938c60113963da342dcb7de2252cffbeaa21d36f518e203f19a43da74d85f2d"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, Network module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "Network Information" ascii wide
		$win_1 = "Network Shares" ascii wide
		$win_2 = "Permissions.*" ascii wide
		$win_3 = "Network Ifaces and known hosts" ascii wide
		$win_4 = "Enumerating IPv4 connections" ascii wide
		$win_5 = "Showing only DENY rules" ascii wide
		$win_6 = "File Permissions.*|Folder Permissions.*" ascii wide
		$win_7 = "DNS cached --limit" ascii wide
		$win_8 = "SELECT * FROM win32_networkconnection" ascii wide
		$win_9 = "Enumerating Internet settings," ascii wide

	condition:
		5 of them
}
