rule webshell_webshells_new_jspyyy
{
	meta:
		description = "Web shells - generated from file jspyyy.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"

	condition:
		all of them
}
