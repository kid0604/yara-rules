rule remview_2003_04_22
{
	meta:
		description = "Webshells Auto-generated - file remview_2003_04_22.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "17d3e4e39fbca857344a7650f7ea55e3"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""

	condition:
		all of them
}
