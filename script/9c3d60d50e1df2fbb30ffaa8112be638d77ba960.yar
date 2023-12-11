rule chinese_spam_spreader : webshell
{
	meta:
		author = "Vlad https://github.com/vlad-s"
		date = "2016/07/18"
		description = "Catches chinese PHP spam files (autospreaders)"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a = "User-Agent: aQ0O010O"
		$b = "<font color='red'><b>Connection Error!</b></font>"
		$c = /if ?\(\$_POST\[Submit\]\) ?{/

	condition:
		all of them
}
