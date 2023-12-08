import "pe"

rule servpw
{
	meta:
		description = "Detects a tool used by APT groups - file servpw.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46"
		hash2 = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Unable to open target process: %d, pid %d" fullword ascii
		$s2 = "LSASS.EXE" fullword wide
		$s3 = "WriteProcessMemory failed: %d" fullword ascii
		$s4 = "lsremora64.dll" fullword ascii
		$s5 = "CreateRemoteThread failed: %d" fullword ascii
		$s6 = "Thread code: %d, path: %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 3 of them ) or ( all of them )
}
