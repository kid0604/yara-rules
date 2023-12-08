rule webshell_Server_Variables
{
	meta:
		description = "Web Shell - file Server Variables.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "47fb8a647e441488b30f92b4d39003d7"
		os = "windows"
		filetype = "script"

	strings:
		$s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
		$s9 = "Variable Name</B></font></p>" fullword

	condition:
		all of them
}
