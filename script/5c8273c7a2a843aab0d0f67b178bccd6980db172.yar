rule WebShell__findsock_php_findsock_shell_php_reverse_shell
{
	meta:
		description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "5622c9841d76617bfc3cd4cab1932d8349b7044f"
		hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
		hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "// me at pentestmonkey@pentestmonkey.net" fullword

	condition:
		all of them
}
