rule WebShell_JspWebshell_1_2_2
{
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "184fc72b51d1429c44a4c8de43081e00967cf86b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
		$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
		$s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
		$s15 = "endPoint=random1.getFilePointer();" fullword
		$s20 = "if (request.getParameter(\"command\") != null) {" fullword

	condition:
		3 of them
}
