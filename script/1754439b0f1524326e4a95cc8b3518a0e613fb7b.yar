rule webshell_phpshell_2_1_pwhash
{
	meta:
		description = "Web Shell - file pwhash.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ba120abac165a5a30044428fac1970d8"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi"
		$s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\","

	condition:
		1 of them
}
