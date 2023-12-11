import "pe"

rule MALWARE_Win_PWSH_PoshCookieStealer
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell PoshCookieStealer"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "\\User Data\\default\\Network\\Cookies" ascii nocase
		$s2 = "Send-ToEmail" ascii
		$s3 = "[Security.Cryptography.ProtectedData]::Unprotect($" ascii
		$s4 = "$($env:LOCALAPPDATA)\\" ascii
		$s5 = "$($env:HOMEPATH)\\" ascii
		$s6 = "|ForEach-Object ToString X2) -join ''" ascii
		$s7 = ".Attachments.Add($" ascii

	condition:
		5 of them
}
