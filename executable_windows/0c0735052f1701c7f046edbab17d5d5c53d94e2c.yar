rule Windows_Hacktool_WinPEAS_ng_cae025b1
{
	meta:
		author = "Elastic Security"
		id = "cae025b1-bc2a-4eea-a1c1-c82d6e4fd71f"
		fingerprint = "3e407824b258ef66ac6883d4c5dd3efeb0f744f8f64b099313cf83e96f9e968a"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, Process info module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "Processes Information" ascii wide
		$win_1 = "Interesting Processes -non Microsoft-" ascii wide
		$win_2 = "Permissions:.*" ascii wide
		$win_3 = "Possible DLL Hijacking.*" ascii wide
		$win_4 = "ExecutablePath" ascii wide
		$win_5 = "Vulnerable Leaked Handlers" ascii wide
		$win_6 = "Possible DLL Hijacking folder:" ascii wide
		$win_7 = "Command Line:" ascii wide

	condition:
		5 of them
}
