rule webshell_PHP_r57142
{
	meta:
		description = "Web Shell - file r57142.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword

	condition:
		all of them
}
