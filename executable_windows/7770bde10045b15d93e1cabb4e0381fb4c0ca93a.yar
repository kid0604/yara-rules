rule Windows_Hacktool_WinPEAS_ng_413caa6b
{
	meta:
		author = "Elastic Security"
		id = "413caa6b-90b7-4763-97b3-49aeb5a97cf6"
		fingerprint = "80b32022a69be8fc1d7e146c3c03623b51e2ee4206eb5f70be753477d68800d5"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, event module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "Interesting Events information" ascii wide
		$win_1 = "PowerShell events" ascii wide
		$win_2 = "Created (UTC)" ascii wide
		$win_3 = "Printing Account Logon Events" ascii wide
		$win_4 = "Subject User Name" ascii wide
		$win_5 = "Target User Name" ascii wide
		$win_6 = "NTLM relay might be possible" ascii wide
		$win_7 = "You can obtain NetNTLMv2" ascii wide
		$win_8 = "The following users have authenticated" ascii wide
		$win_9 = "You must be an administrator" ascii wide

	condition:
		5 of them
}
