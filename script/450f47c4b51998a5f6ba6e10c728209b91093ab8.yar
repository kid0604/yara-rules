rule webshell_PHP_Shell_x3
{
	meta:
		description = "Web Shell - file PHP Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
		$s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("

	condition:
		2 of them
}
