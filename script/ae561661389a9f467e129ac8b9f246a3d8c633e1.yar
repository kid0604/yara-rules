rule webshell_Inderxer
{
	meta:
		description = "Web Shell - file Inderxer.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "9ea82afb8c7070817d4cdf686abe0300"
		os = "windows"
		filetype = "script"

	strings:
		$s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"

	condition:
		all of them
}
