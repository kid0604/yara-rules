rule Weevely_Webshell_alt_1 : webshell
{
	meta:
		description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
		author = "Florian Roth"
		reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"
		date = "2014/12/14"
		score = 60
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$php = "<?php" ascii
		$s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
		$s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
		$s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
		$s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii

	condition:
		$php at 0 and all of ($s*) and filesize >570 and filesize <800
}
