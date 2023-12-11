rule WebShell_mysql_tool
{
	meta:
		description = "PHP Webshells Github Archive - file mysql_tool.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
		$s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword

	condition:
		2 of them
}
