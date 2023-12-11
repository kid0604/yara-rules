rule webshell_jsp_web
{
	meta:
		description = "Web Shell - file web.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "4bc11e28f5dccd0c45a37f2b541b2e98"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."

	condition:
		all of them
}
