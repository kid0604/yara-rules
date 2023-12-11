rule dat_report
{
	meta:
		description = "Chinese Hacktool Set - file report.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
		$s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <480KB and all of them
}
