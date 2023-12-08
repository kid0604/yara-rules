rule chinese_spam_echoer : webshell
{
	meta:
		author = "Vlad https://github.com/vlad-s"
		date = "2016/07/18"
		description = "Catches chinese PHP spam files (printers)"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a = "set_time_limit(0)"
		$b = "date_default_timezone_set('PRC');"
		$c = "$Content_mb;"
		$d = "/index.php?host="

	condition:
		all of them
}
