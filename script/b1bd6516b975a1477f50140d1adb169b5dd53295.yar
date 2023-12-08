rule webshell_asp_list
{
	meta:
		description = "Web Shell - file list.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1cfa493a165eb4b43e6d4cc0f2eab575"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
		$s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword

	condition:
		all of them
}
