rule webshell_jsp_12302
{
	meta:
		description = "Web Shell - file 12302.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a3930518ea57d899457a62f372205f7f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
		$s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
		$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""

	condition:
		all of them
}
