rule webshell_jsp_123_alt_1
{
	meta:
		description = "Web Shell - file 123.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c691f53e849676cac68a38d692467641"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
		$s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
		$s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword

	condition:
		all of them
}
