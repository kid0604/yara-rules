rule APT_MAL_CN_Wocao_webshell_console_jsp
{
	meta:
		description = "Strings from the console.jsp webshell"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows,linux"
		filetype = "script"

	strings:
		$a = "String strLogo = request.getParameter(\"image\")"
		$b = "!strLogo.equals(\"web.gif\")"
		$c = "<font color=red>Save Failed!</font>"
		$d = "<font color=red>Save Success!</font>"
		$e = "Save path:<br><input type=text"
		$f = "if (newfile.exists() && newfile.length()>0) { out.println"

	condition:
		1 of them
}
