rule r57shell_2
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8023394542cddf8aee5dec6072ed02b5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"

	condition:
		all of them
}
