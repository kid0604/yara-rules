rule clearlog
{
	meta:
		description = "Detects Fireball malware - file clearlog.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "14093ce6d0fe8ab60963771f48937c669103842a0400b8d97f829b33c420f7e3"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\ClearLog\\Release\\logC.pdb" ascii
		$s1 = "C:\\Windows\\System32\\cmd.exe /c \"\"" fullword wide
		$s2 = "logC.dll" fullword ascii
		$s3 = "hhhhh.exe" fullword wide
		$s4 = "ttttt.exe" fullword wide
		$s5 = "Logger Name:" fullword ascii
		$s6 = "cle.log.1" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and $x1 or 2 of them )
}
