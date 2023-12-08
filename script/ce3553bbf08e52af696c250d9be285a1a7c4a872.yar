rule Tools_2014
{
	meta:
		description = "Chinese Hacktool Set - file 2014.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "74518faf08637c53095697071db09d34dbe8d676"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
		$s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
		$s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii

	condition:
		filesize <715KB and all of them
}
