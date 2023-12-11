rule Windows_Hacktool_WinPEAS_ng_23fee092
{
	meta:
		author = "Elastic Security"
		id = "23fee092-f1ff-4d9e-9873-0a68360efb42"
		fingerprint = "4420faa4da440a9e2b1d8eadef2a1864c078fccf391ac3d7872abe1d738c926e"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, File analysis module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "File Analysis" ascii wide
		$win_1 = "apache*" ascii wide
		$win_2 = "tomcat*" ascii wide
		$win_3 = "had a timeout (ReDoS avoided but regex" ascii wide
		$win_4 = "Error looking for regex" ascii wide
		$win_5 = "Looking for secrets inside" ascii wide
		$win_6 = "files with ext" ascii wide
		$win_7 = "(limited to" ascii wide

	condition:
		4 of them
}
