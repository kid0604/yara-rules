rule Windows_Trojan_CobaltStrike_7f8da98a
{
	meta:
		author = "Elastic Security"
		id = "7f8da98a-3336-482b-91da-82c7cef34c62"
		fingerprint = "c375492960a6277bf665bea86302cec774c0d79506e5cb2e456ce59f5e68aa2e"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "e3bc2bec4a55ad6cfdf49e5dbd4657fc704af1758ca1d6e31b83dcfb8bf0f89d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan CobaltStrike"
		filetype = "executable"

	strings:
		$a1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }

	condition:
		all of them
}
