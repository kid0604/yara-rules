rule webshell_webshells_new_php5
{
	meta:
		description = "Web shells - generated from file php5.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "cf2ab009cbd2576a806bfefb74906fdf"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"

	condition:
		all of them
}
