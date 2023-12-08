rule FSO_s_RemExp_2
{
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b69670ecdbb40012c73686cd22696eeb"
		os = "windows"
		filetype = "script"

	strings:
		$s2 = " Then Response.Write \""
		$s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"

	condition:
		all of them
}
