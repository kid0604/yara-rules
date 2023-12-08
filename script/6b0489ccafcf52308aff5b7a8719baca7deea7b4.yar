rule WebShell_JspWebshell_1_2
{
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0bed4a1966117dd872ac9e8dceceb54024a030fa"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
		$s1 = "String password=request.getParameter(\"password\");" fullword
		$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
		$s7 = "String editfile=request.getParameter(\"editfile\");" fullword
		$s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
		$s12 = "password = (String)session.getAttribute(\"password\");" fullword

	condition:
		3 of them
}
