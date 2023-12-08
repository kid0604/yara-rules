rule webshell_PH_Vayv_PH_Vayv
{
	meta:
		description = "Web Shell - file PH Vayv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "35fb37f3c806718545d97c6559abd262"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
		$s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"

	condition:
		1 of them
}
