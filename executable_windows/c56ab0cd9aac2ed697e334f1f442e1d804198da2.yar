rule RemoteCmd
{
	meta:
		description = "Detects a remote access tool used by APT groups - file RemoteCmd.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		modified = "2022-12-21"
		hash1 = "5264d1de687432f8346617ac88ffcb31e025e43fc3da1dad55882b17b44f1f8b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "RemoteCmd.exe" fullword wide
		$s2 = "\\Release\\RemoteCmd.pdb" ascii
		$s3 = "RemoteCmd [ComputerName] [Executable] [Param1] [Param2] ..." fullword wide
		$s4 = "http://{0}:65101/CommandEngine" fullword wide
		$s5 = "Brenner.RemoteCmd.Client" fullword ascii
		$s6 = "$b1888995-1ee5-4f6d-82df-d2ab8ae73d63" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and 2 of them ) or (4 of them )
}
