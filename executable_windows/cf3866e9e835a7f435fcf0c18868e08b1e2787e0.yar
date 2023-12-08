rule MarathonTool
{
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "084a27cd3404554cc799d0e689f65880e10b59e3"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "MarathonTool" ascii
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
		$s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1040KB and all of them
}
