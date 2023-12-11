rule Txt_asp1
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file asp1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "95934d05f0884e09911ea9905c74690ace1ef653"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
		$s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
		$s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
		$s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii

	condition:
		filesize <70KB and 2 of them
}
