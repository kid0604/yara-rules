rule webshell_C99madShell_v_3_0_smowu
{
	meta:
		description = "Web Shell - file smowu.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "74e1e7c7a6798f1663efb42882b85bee"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for"
		$s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty"

	condition:
		1 of them
}
