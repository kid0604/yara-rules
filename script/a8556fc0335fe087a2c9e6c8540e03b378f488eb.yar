rule Txt_shell
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file shell.c"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "8342b634636ef8b3235db0600a63cc0ce1c06b62"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
		$s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
		$s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
		$s4 = "char shell[]=\"/bin/sh\";" fullword ascii
		$s5 = "connect back door\\n\\n\");" fullword ascii

	condition:
		filesize <2KB and 2 of them
}
