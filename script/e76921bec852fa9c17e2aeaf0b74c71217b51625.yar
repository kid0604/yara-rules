rule Tools_cmd
{
	meta:
		description = "Chinese Hacktool Set - file cmd.jSp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "02e37b95ef670336dc95331ec73dbb5a86f3ba2b"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
		$s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
		$s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
		$s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
		$s4 = "while((a=in.read(b))!=-1){" fullword ascii
		$s5 = "out.println(new String(b));" fullword ascii
		$s6 = "out.print(\"</pre>\");" fullword ascii
		$s7 = "out.print(\"<pre>\");" fullword ascii
		$s8 = "int a = -1;" fullword ascii
		$s9 = "byte[] b = new byte[2048];" fullword ascii

	condition:
		filesize <3KB and 7 of them
}
