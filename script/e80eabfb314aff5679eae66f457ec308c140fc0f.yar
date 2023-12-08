rule webshell_webshell_cnseay02_1
{
	meta:
		description = "Web Shell - file webshell-cnseay02-1.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "95fc76081a42c4f26912826cb1bd24b1"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU"

	condition:
		all of them
}
