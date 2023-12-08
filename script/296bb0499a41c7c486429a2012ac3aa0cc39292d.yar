rule webshell_PHP_g00nv13
{
	meta:
		description = "Web Shell - file g00nv13.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "35ad2533192fe8a1a76c3276140db820"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
		$s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"

	condition:
		all of them
}
