rule webshell_minupload
{
	meta:
		description = "Web Shell - file minupload.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ec905a1395d176c27f388d202375bdf9"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
		$s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"

	condition:
		all of them
}
