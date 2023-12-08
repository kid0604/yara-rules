rule FSO_s_casus15
{
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8d155b4239d922367af5d0a1b89533a3"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"

	condition:
		all of them
}
