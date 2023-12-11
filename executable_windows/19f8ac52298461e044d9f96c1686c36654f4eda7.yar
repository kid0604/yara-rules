rule CN_Honker_ScanHistory
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ScanHistory.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "14c31e238924ba3abc007dc5a3168b64d7b7de8d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ScanHistory.exe" fullword wide
		$s2 = ".\\Report.dat" fullword wide
		$s3 = "select  * from  Results order by scandate desc" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
