rule webshell_Dx_Dx
{
	meta:
		description = "Web Shell - file Dx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s9 = "class=linelisting><nobr>POST (php eval)</td><"

	condition:
		1 of them
}
