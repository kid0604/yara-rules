rule Windows_Hacktool_WinPEAS_ng_bcedc8b2
{
	meta:
		author = "Elastic Security"
		id = "bcedc8b2-d9e1-45cd-94b4-a19a3ed8c0f9"
		fingerprint = "039ea2f11596d6a8d5da05944796424ee6be66e16742676bbb2dc3fcf274cf4a"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, User info module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "Users Information" ascii wide
		$win_1 = "docker|Remote |DNSAdmins|AD Recycle Bin|" ascii wide
		$win_2 = "NotChange|NotExpi" ascii wide
		$win_3 = "Current Token privileges" ascii wide
		$win_4 = "Clipboard text" ascii wide
		$win_5 = "{0,-10}{1,-15}{2,-15}{3,-25}{4,-10}{5}" ascii wide
		$win_6 = "Ever logged users" ascii wide
		$win_7 = "Some AutoLogon credentials were found" ascii wide
		$win_8 = "Current User Idle Time" ascii wide
		$win_9 = "DsRegCmd.exe /status" ascii wide

	condition:
		5 of them
}
