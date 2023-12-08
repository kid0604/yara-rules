rule webshell_PHP_redcod
{
	meta:
		description = "Web Shell - file redcod.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5c1c8120d82f46ff9d813fbe3354bac5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
		$s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword

	condition:
		all of them
}
