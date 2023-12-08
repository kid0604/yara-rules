rule webshell_jsp_cmd
{
	meta:
		description = "Web Shell - file cmd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5391c4a8af1ede757ba9d28865e75853"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword

	condition:
		all of them
}
