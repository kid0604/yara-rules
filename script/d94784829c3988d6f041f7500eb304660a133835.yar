rule webshell_PHP_b37
{
	meta:
		description = "Web Shell - file b37.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "0421445303cfd0ec6bc20b3846e30ff0"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc"

	condition:
		all of them
}
