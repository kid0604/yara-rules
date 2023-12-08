rule Windows_Hacktool_WinPEAS_ng_4db2c852
{
	meta:
		author = "Elastic Security"
		id = "4db2c852-6c03-4672-9250-f80671b93e1b"
		fingerprint = "f05862b7b74cb4741aa953d725336005cdb9b1d50a92ce8bb295114e27f81b2a"
		creation_date = "2022-12-21"
		last_modified = "2023-02-01"
		description = "WinPEAS detection based on the dotNet binary, System info module"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$win_0 = "No prompting|PromptForNonWindowsBinaries" ascii wide
		$win_1 = "System Information" ascii wide
		$win_2 = "Showing All Microsoft Updates" ascii wide
		$win_3 = "GetTotalHistoryCount" ascii wide
		$win_4 = "PS history size:" ascii wide
		$win_5 = "powershell_transcript*" ascii wide
		$win_6 = "Check what is being logged" ascii wide
		$win_7 = "WEF Settings" ascii wide
		$win_8 = "CredentialGuard is active" ascii wide
		$win_9 = "cachedlogonscount is" ascii wide

	condition:
		5 of them
}
