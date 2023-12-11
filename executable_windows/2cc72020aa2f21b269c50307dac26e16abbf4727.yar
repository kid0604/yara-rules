rule CmdShell64
{
	meta:
		description = "Chinese Hacktool Set - file CmdShell64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b92510475d95ae5e7cd6ec4c89852e8af34acf1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
		$s2 = "ServiceCmdShell" fullword ascii
		$s3 = "<!-- If your application is designed to work with Windows 8.1, uncomment the fol" ascii
		$s4 = "ServiceSystemShell" fullword wide
		$s5 = "[Root@CmdShell ~]#" fullword wide
		$s6 = "Hello Man 2015 !" fullword wide
		$s7 = "CmdShell" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 4 of them
}
