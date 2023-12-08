rule PHP_Backdoor_v1
{
	meta:
		description = "Webshells Auto-generated - file PHP Backdoor v1.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0506ba90759d11d78befd21cabf41f3d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
		$s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"

	condition:
		all of them
}
