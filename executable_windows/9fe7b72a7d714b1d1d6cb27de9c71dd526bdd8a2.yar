rule SUSP_PS1_Msdt_Execution_May22
{
	meta:
		description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190 / Follina exploitation"
		author = "Nasreddine Bencherchali, Christian Burkard"
		date = "2022-05-31"
		modified = "2022-07-08"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		score = 75
		os = "windows"
		filetype = "executable"

	strings:
		$a = "PCWDiagnostic" ascii wide fullword
		$sa1 = "msdt.exe" ascii wide
		$sa2 = "msdt " ascii wide
		$sa3 = "ms-msdt" ascii wide
		$sb1 = "/af " ascii wide
		$sb2 = "-af " ascii wide
		$sb3 = "IT_BrowseForFile=" ascii wide
		$fp1 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00
               46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00
               00 00 70 00 63 00 77 00 72 00 75 00 6E 00 2E 00
               65 00 78 00 65 00 }
		$fp2 = "FilesFullTrust" wide

	condition:
		filesize <10MB and $a and 1 of ($sa*) and 1 of ($sb*) and not 1 of ($fp*)
}
