rule r57shell_3
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "87995a49f275b6b75abe2521e03ac2c0"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<b>\".$_POST['cmd']"

	condition:
		all of them
}
