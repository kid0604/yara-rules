rule webshell_webshell_cnseay_x
{
	meta:
		description = "Web Shell - file webshell-cnseay-x.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a0f9f7f5cd405a514a7f3be329f380e5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_"

	condition:
		all of them
}
