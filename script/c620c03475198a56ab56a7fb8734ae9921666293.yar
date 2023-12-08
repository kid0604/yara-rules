rule INDICATOR_KB_ID_PowerShellCookieStealer
{
	meta:
		author = "ditekShen"
		description = "Detects email accounts used for exfiltration observed in PowerShellCookieStealer"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "senmn0w@gmail.com" ascii wide nocase
		$s2 = "mohamed.trabelsi.ena2@gmail.com" ascii wide nocase

	condition:
		any of them
}
