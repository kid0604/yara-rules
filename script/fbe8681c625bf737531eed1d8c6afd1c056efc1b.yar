rule webshell_jsp_up
{
	meta:
		description = "Web Shell - file up.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "515a5dd86fe48f673b72422cccf5a585"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword

	condition:
		all of them
}
