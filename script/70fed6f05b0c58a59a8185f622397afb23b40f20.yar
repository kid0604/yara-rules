rule klasvayv_asp
{
	meta:
		description = "Semi-Auto-generated  - file klasvayv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b3e64bf8462fc3d008a3d1012da64ef"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "set aktifklas=request.querystring(\"aktifklas\")"
		$s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>"
		$s3 = "<font color=\"#858585\">www.aventgrup.net"
		$s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT"

	condition:
		1 of them
}
