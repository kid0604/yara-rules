rule webshell_jsp_zx
{
	meta:
		description = "Web Shell - file zx.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "67627c264db1e54a4720bd6a64721674"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"

	condition:
		all of them
}
