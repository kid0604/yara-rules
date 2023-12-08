rule APT_MAL_CN_Wocao_webshell_ver_jsp
{
	meta:
		description = "Strings from the ver.jsp webshell"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a = "String strLogo = request.getParameter(\"id\")"
		$b = "!strLogo.equals(\"256\")"
		$c = "boolean chkos = msg.startsWith"
		$d = "while((c = er.read()) != -1)"
		$e = "out.print((char)c);}in.close()"
		$f = "out.print((char)c);}er.close()"

	condition:
		1 of them
}
