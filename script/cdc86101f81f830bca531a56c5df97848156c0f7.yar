rule STNC_php_php
{
	meta:
		description = "Semi-Auto-generated  - file STNC.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2e56cfd5b5014cbbf1c1e3f082531815"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "drmist.ru" fullword
		$s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80"
		$s2 = "STNC WebShell"
		$s3 = "http://www.security-teams.net/index.php?showtopic="

	condition:
		1 of them
}
