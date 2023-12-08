rule webshell_B374kPHP_B374k
{
	meta:
		description = "Web Shell - file B374k.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "bed7388976f8f1d90422e8795dff1ea6"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Http://code.google.com/p/b374k-shell" fullword
		$s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'"
		$s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
		$s4 = "B374k Vip In Beautify Just For Self" fullword

	condition:
		1 of them
}
