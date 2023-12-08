rule webshell_Safe_mode_breaker
{
	meta:
		description = "Web Shell - file Safe mode breaker.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5bd07ccb1111950a5b47327946bfa194"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
		$s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."

	condition:
		1 of them
}
