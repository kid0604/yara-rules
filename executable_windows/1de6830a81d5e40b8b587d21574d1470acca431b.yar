rule Tools_termsrv
{
	meta:
		description = "Chinese Hacktool Set - file termsrv.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "294a693d252f8f4c85ad92ee8c618cebd94ef247"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Iv\\SmSsWinStationApiPort" fullword ascii
		$s2 = " TSInternetUser " fullword wide
		$s3 = "KvInterlockedCompareExchange" fullword ascii
		$s4 = " WINS/DNS " fullword wide
		$s5 = "winerror=%1" fullword wide
		$s6 = "TermService " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1150KB and all of them
}
