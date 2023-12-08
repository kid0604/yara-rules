rule webshell_webshells_new_JJjsp3
{
	meta:
		description = "Web shells - generated from file JJjsp3.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "949ffee1e07a1269df7c69b9722d293e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"

	condition:
		all of them
}
