rule Windows_Hacktool_WinPEAS_ng_4a9b9603
{
	meta:
		author = "Elastic Security"
		id = "4a9b9603-7b42-4a85-b66a-7f4ec0013338"
		fingerprint = "2a7b0e1d850fa6a24f590755ae5610309741e520e4b2bc067f54a8e086444da2"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, Services info module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "Services Information" ascii wide
		$win_1 = "Interesting Services -non Microsoft-" ascii wide
		$win_2 = "FilteredPath" ascii wide
		$win_3 = "YOU CAN MODIFY THIS SERVICE:" ascii wide
		$win_4 = "Modifiable Services" ascii wide
		$win_5 = "AccessSystemSecurity" ascii wide
		$win_6 = "Looks like you cannot change the" ascii wide
		$win_7 = "Checking write permissions in" ascii wide

	condition:
		4 of them
}
