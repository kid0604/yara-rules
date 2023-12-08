rule Windows_Hacktool_WinPEAS_ng_66197d54
{
	meta:
		author = "Elastic Security"
		id = "66197d54-3cd2-4006-807d-24d0e0d9e25a"
		fingerprint = "951f0ca036a0ab0cf2299382049eecb78f35325470f222c6db90a819b9414083"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, application module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "Possible DLL Hijacking, folder is writable" ascii wide
		$win_1 = "FolderPerms:.*" ascii wide
		$win_2 = "interestingFolderRights" ascii wide
		$win_3 = "(Unquoted and Space detected)" ascii wide
		$win_4 = "interestingFolderRights" ascii wide
		$win_5 = "RegPerms: .*" ascii wide
		$win_6 = "Permissions file: {3}" ascii wide
		$win_7 = "Permissions folder(DLL Hijacking):" ascii wide

	condition:
		4 of them
}
