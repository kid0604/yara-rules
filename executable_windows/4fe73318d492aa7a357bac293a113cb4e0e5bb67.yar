rule chrome_elf
{
	meta:
		description = "Detects Fireball malware - file chrome_elf.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "e4d4f6fbfbbbf3904ca45d296dc565138a17484c54aebbb00ba9d57f80dfe7e5"
		os = "windows"
		filetype = "executable"

	strings:
		$x2 = "schtasks /Create /SC HOURLY /MO %d /ST 00:%02d:00 /TN \"%s\" /TR \"%s\" /RU \"SYSTEM\"" fullword wide
		$s6 = "aHR0cDovL2R2Mm0xdXVtbnNndHUuY2xvdWRmcm9udC5uZXQvdjQvZ3RnLyVzP2FjdGlvbj12aXNpdC5jaGVsZi5pbnN0YWxs" fullword ascii
		$s7 = "QueryInterface call failed for IExecAction: %x" fullword ascii
		$s10 = "%s %s,Rundll32_Do %s" fullword wide
		$s13 = "Failed to create an instance of ITaskService: %x" fullword ascii
		$s16 = "Rundll32_Do" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 4 of them )
}
