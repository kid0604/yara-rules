rule webshell_jsp_guige02
{
	meta:
		description = "Web Shell - file guige02.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a3b8b2280c56eaab777d633535baf21d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
		$s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"

	condition:
		all of them
}
