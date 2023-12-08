rule FSO_s_phpinj_2
{
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "dd39d17e9baca0363cc1c3664e608929"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"

	condition:
		all of them
}
