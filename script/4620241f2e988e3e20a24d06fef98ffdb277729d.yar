rule webshell_cmd_win32
{
	meta:
		description = "Web Shell - file cmd_win32.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "cc4d4d6cc9a25984aa9a7583c7def174"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam"
		$s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword

	condition:
		2 of them
}
