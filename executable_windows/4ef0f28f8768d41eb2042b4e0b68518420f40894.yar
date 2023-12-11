rule WindowsShell_s3
{
	meta:
		description = "Detects simple Windows shell - file s3.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "\\\\.\\pipe\\%08X" fullword ascii
		$s3 = "get <remote> <local> - download file" fullword ascii
		$s4 = "[ simple remote shell for windows v3" fullword ascii
		$s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s6 = "put <local> <remote> - upload file" fullword ascii
		$s7 = "term                 - terminate remote client" fullword ascii
		$s8 = "[ downloading \"%s\" to \"%s\"" fullword ascii
		$s9 = "-l           Listen for incoming connections" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <150KB and 2 of them ) or (5 of them )
}
