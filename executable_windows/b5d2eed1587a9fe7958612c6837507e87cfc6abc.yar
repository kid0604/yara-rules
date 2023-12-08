rule CN_Honker_WebRobot
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebRobot.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "af054994c911b4301490344fca4bb19a9f394a8f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%d-%02d-%02d %02d^%02d^%02d ScanReprot.htm" fullword ascii
		$s2 = "\\log\\ProgramDataFile.dat" ascii
		$s3 = "\\data\\FilterKeyword.txt" ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
