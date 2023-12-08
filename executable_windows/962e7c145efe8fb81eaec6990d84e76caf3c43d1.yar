rule CN_Honker_Fpipe_FPipe
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file FPipe.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 50
		hash = "a2c51c6fa93a3dfa14aaf31fb1c48a3a66a32d11"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Unable to create TCP listen socket. %s%d" fullword ascii
		$s2 = "http://www.foundstone.com" fullword ascii
		$s3 = "%s %s port %d. Address is already in use" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
