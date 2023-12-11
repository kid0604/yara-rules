rule webshell_jsp_cmdjsp
{
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b815611cc39f17f05a73444d699341d4"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword

	condition:
		all of them
}
