rule webshell_Crystal_Crystal
{
	meta:
		description = "Web Shell - file Crystal.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "fdbf54d5bf3264eb1c4bff1fac548879"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
		$s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"

	condition:
		all of them
}
