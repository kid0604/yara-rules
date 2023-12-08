rule r57shell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file r57shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d28445de424594a5f14d0fe2a7c4e94f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
		$s2 = "RusH security team"
		$s3 = "'ru_text12' => 'back-connect"
		$s4 = "<title>r57shell</title>"

	condition:
		1 of them
}
