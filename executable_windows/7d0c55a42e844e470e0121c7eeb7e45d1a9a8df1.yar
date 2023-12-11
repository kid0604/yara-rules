rule hkmjjiis6
{
	meta:
		description = "Chinese Hacktool Set - file hkmjjiis6.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "user32.dlly" ascii
		$s3 = "runtime error" ascii
		$s4 = "WinSta0\\Defau" ascii
		$s5 = "AppIDFlags" fullword ascii
		$s6 = "GetLag" fullword ascii
		$s7 = "* FROM IIsWebInfo" ascii
		$s8 = "wmiprvse.exe" ascii
		$s9 = "LookupAcc" ascii

	condition:
		uint16(0)==0x5a4d and filesize <70KB and all of them
}
