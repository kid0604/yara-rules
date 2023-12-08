rule CN_Honker_CleanIISLog
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CleanIISLog.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Usage: CleanIISLog <LogFile>|<.> <CleanIP>|<.>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
