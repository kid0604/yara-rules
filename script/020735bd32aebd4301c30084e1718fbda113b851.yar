rule backup_php_often_with_c99shell
{
	meta:
		description = "Semi-Auto-generated  - file backup.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "aeee3bae226ad57baf4be8745c3f6094"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "#phpMyAdmin MySQL-Dump" fullword
		$s2 = ";db_connect();header('Content-Type: application/octetstr"
		$s4 = "$data .= \"#Database: $database" fullword

	condition:
		all of them
}
