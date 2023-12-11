rule OracleScan
{
	meta:
		description = "Chinese Hacktool Set - file OracleScan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
		$s2 = "\\Borland\\Delphi\\RTL" fullword ascii
		$s3 = "USER_NAME" ascii
		$s4 = "FROMWWHERE" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
