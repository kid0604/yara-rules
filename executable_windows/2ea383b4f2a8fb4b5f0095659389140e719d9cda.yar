rule CN_Honker_super_Injection1
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file super Injection1.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8ff2df40c461f6c42b92b86095296187f2b59b14"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "ScanInject.log" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
