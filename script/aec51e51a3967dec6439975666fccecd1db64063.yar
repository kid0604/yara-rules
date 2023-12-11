rule warfiles_cmd : webshell
{
	meta:
		description = "Laudanum Injector Tools - file cmd.jsp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ae3d837e7b362de738cf7fad78eded0dccf601f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii
		$s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii
		$s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
		$s4 = "String disr = dis.readLine();" fullword ascii

	condition:
		filesize <2KB and all of them
}
