rule CN_Honker_WordpressScanner
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WordpressScanner.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0b3c5015ba3616cbc616fc9ba805fea73e98bc83"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s1 = "(http://www.eyuyan.com)" fullword wide
		$s2 = "GetConnectString" fullword ascii
		$s4 = "#if !defined(AFX_RESOURCE_DLL) || defined(AFX_TARG_CHS)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
