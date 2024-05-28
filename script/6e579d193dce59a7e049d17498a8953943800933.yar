import "pe"

rule MALWARE_Win_ScoutElitePS
{
	meta:
		author = "ditekshen"
		description = "Detects actor PowerShell tool designed to steal browsers session cookie and passwords on-disk and in-memory"
		reference = "https://github.com/ditekshen/back-in-2017"
		os = "windows"
		filetype = "script"

	strings:
		$cnc1 = "http://beginpassport.com" ascii wide nocase
		$cnc2 = "f_dump.php" ascii wide nocase
		$cnc3 = "c_dump.php" ascii wide nocase
		$cnc4 = "o_dump.php" ascii wide nocase
		$db1 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii wide nocase
		$db2 = "\\Mozilla\\Firefox\\Profiles\\*.default" ascii wide nocase
		$db3 = "\\Opera Software\\Opera Stable\\Cookies" ascii wide nocase
		$db4 = "$($env:LOCALAPPDATA)\\Google\\Chrome\\User Data\\Default" ascii nocase
		$db5 = "$($env:APPDATA)\\Mozilla\\Firefox\\Profiles\\*.default" ascii nocase
		$db6 = "$($env:APPDATA)\\Opera Software\\Opera Stable" ascii nocase
		$cond1 = "SSID" ascii wide
		$cond2 = "MSPAuth" ascii wide
		$cond3 = "\"'T'\"" ascii wide
		$cond4 = "SNS_AA" ascii wide
		$cond5 = "X-APPLE-WEBAUTH-TOKEN" ascii wide
		$sql1 = "SELECT * FROM 'cookies' WHERE host_key LIKE $" ascii wide nocase
		$sql2 = "SELECT * FROM 'moz_cookies' WHERE host LIKE $" ascii wide nocase
		$sql3 = "SELECT origin_url, username_value ,password_value FROM 'logins'" ascii nocase
		$def1 = "Add-Type -AssemblyName System.Security" ascii wide nocase
		$def2 = "System.Security.SecureString" ascii wide nocase
		$def3 = "ConvertFrom-SecureString" ascii wide nocase
		$def4 = "[System.Security.Cryptography.ProtectedData]::Unprotect(" ascii wide nocase
		$def5 = "[Security.Cryptography.DataProtectionScope]::LocalMachine" ascii wide nocase
		$def6 = "[Security.Cryptography.DataProtectionScope]::CurrentUser" ascii wide nocase
		$def7 = "System.Data.SQLite.SQLiteConnection" ascii wide nocase
		$def8 = "[Environment]::OSVersion.ToString().Replace(\"Microsoft Windows \"," ascii wide nocase
		$def9 = "Start-Sleep" ascii wide nocase

	condition:
		(1 of ($cnc*) and any of ($db*) and any of ($cond*) and any of ($sql*) and 7 of ($def*)) or ( all of them )
}
