rule FSO_s_remview_2
{
	meta:
		description = "Webshells Auto-generated - file remview.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b4a09911a5b23e00b55abe546ded691c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<xmp>$out</"
		$s1 = ".mm(\"Eval PHP code\")."

	condition:
		all of them
}
