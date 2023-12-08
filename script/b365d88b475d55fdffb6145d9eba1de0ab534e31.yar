rule webshell_ASP_cmd
{
	meta:
		description = "Web Shell - file cmd.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "97af88b478422067f23b001dd06d56a9"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword

	condition:
		all of them
}
