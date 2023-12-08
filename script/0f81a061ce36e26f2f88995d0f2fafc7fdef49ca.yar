rule APT_MAL_CN_Wocao_webshell_index_jsp
{
	meta:
		description = "Strings from the index.jsp socket tunnel"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "X-CMD"
		$x2 = "X-STATUS"
		$x3 = "X-TARGET"
		$x4 = "X-ERROR"
		$a = "out.print(\"All seems fine.\");"

	condition:
		all of ($x*) and $a
}
