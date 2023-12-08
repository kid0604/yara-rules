rule INDICATOR_RTF_EXPLOIT_CVE_2017_0199_1
{
	meta:
		description = "Detects RTF documents potentially exploiting CVE-2017-0199"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$urlmoniker3 = { 45 0a 30 0a 43 0a 39 0a 45 0a 41 0a 37 0a 39 0a 
                         46 0a 39 0a 42 0a 41 0a 43 0a 45 0a 31 0a 31 0a 
                         38 0a 43 0a 38 0a 32 0a 30 0a 30 0a 41 0a 41 0a 
                         30 0a 30 0a 34 0a 42 0a 41 0a 39 0a 30 0a 42 }
		$urlmoniker4 = { 45 0d 0a 30 0d 0a 43 0d 0a 39 0d 0a 45 0d 0a 41
                         0d 0a 37 0d 0a 39 0d 0a 46 0d 0a 39 0d 0a 42 0d 
                         0a 41 0d 0a 43 0d 0a 45 0d 0a 31 0d 0a 31 0d 0a
                         38 0d 0a 43 0d 0a 38 0d 0a 32 0d 0a 30 0d 0a 30
                         0d 0a 41 0d 0a 41 0d 0a 30 0d 0a 30 0d 0a 34 0d
                         0a 42 0d 0a 41 0d 0a 39 0d 0a 30 0d 0a 42 }
		$urlmoniker6 = { 65 0a 30 0a 63 0a 39 0a 65 0a 61 0a 37 0a 39 0a
                         66 0a 39 0a 62 0a 61 0a 63 0a 65 0a 31 0a 31 0a
                         38 0a 63 0a 38 0a 32 0a 30 0a 30 0a 61 0a 61 0a
                         30 0a 30 0a 34 0a 62 0a 61 0a 39 0a 30 0a 62 }
		$urlmoniker7 = { 65 0d 0a 30 0d 0a 63 0d 0a 39 0d 0a 65 0d 0a 61
                         0d 0a 37 0d 0a 39 0d 0a 66 0d 0a 39 0d 0a 62 0d
                         0a 61 0d 0a 63 0d 0a 65 0d 0a 31 0d 0a 31 0d 0a
                         38 0d 0a 63 0d 0a 38 0d 0a 32 0d 0a 30 0d 0a 30
                         0d 0a 61 0d 0a 61 0d 0a 30 0d 0a 30 0d 0a 34 0d
                         0a 62 0d 0a 61 0d 0a 39 0d 0a 30 0d 0a 62 }
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" ascii nocase
		$ole5 = { 64 0a 30 0a 63 0a 66 0a 31 0a 31 0a 65 0a 30 }
		$ole6 = { 64 0d 0a 30 0d 0a 63 0d 0a 66 0d 0a 31 0d 0a 31 0d 0a 65 0d 0a 30 }
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii

	condition:
		uint32(0)==0x74725c7b and 1 of ($urlmoniker*) and 1 of ($ole*) and 1 of ($obj*)
}
