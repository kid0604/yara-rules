rule webshell_caidao_shell_mdb
{
	meta:
		description = "Web Shell - file mdb.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "fbf3847acef4844f3a0d04230f6b9ff9"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<% execute request(\"ice\")%>a " fullword

	condition:
		all of them
}
