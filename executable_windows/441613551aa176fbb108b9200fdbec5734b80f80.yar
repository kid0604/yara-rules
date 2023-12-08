rule XScanLib
{
	meta:
		description = "Chinese Hacktool Set - file XScanLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		os = "windows"
		filetype = "executable"

	strings:
		$s4 = "XScanLib.dll" fullword ascii
		$s6 = "Ports/%s/%d" fullword ascii
		$s8 = "DEFAULT-TCP-PORT" fullword ascii
		$s9 = "PlugCheckTcpPort" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <360KB and all of them
}
