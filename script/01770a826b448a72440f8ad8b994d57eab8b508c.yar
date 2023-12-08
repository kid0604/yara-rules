rule webshell_jsp_sys3
{
	meta:
		description = "Web Shell - file sys3.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b3028a854d07674f4d8a9cf2fb6137ec"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
		$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
		$s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword

	condition:
		all of them
}
