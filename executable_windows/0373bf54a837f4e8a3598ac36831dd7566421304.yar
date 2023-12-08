rule Dos_ch
{
	meta:
		description = "Chinese Hacktool Set - file ch.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "/Churraskito/-->Usage: Churraskito.exe \"command\" " fullword ascii
		$s4 = "fuck,can't find WMI process PID." fullword ascii
		$s5 = "/Churraskito/-->Found token %s " fullword ascii
		$s8 = "wmiprvse.exe" fullword ascii
		$s10 = "SELECT * FROM IIsWebInfo" fullword ascii
		$s17 = "WinSta0\\Default" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <260KB and 3 of them
}
