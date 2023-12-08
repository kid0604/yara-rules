rule webshell_jsp_cmdjsp_2
{
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1b5ae3649f03784e2a5073fa4d160c8b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
		$s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword

	condition:
		all of them
}
