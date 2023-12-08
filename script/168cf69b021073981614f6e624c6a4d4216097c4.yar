rule webshell_remview_fix
{
	meta:
		description = "Web Shell - file remview_fix.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a24b7c492f5f00e2a19b0fa2eb9c3697"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
		$s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n"

	condition:
		1 of them
}
