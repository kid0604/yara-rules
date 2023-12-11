rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_2
{
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8fdd4e0e87c044177e9e1c97084eb5b18e2f1c25"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
		$s3 = "xb5@hotmail.com</FONT></CENTER></B>\");" fullword
		$s4 = "$v = @ini_get(\"open_basedir\");" fullword
		$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword

	condition:
		2 of them
}
