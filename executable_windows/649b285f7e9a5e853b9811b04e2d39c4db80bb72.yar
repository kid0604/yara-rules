rule ChinaChopper_caidao
{
	meta:
		description = "Chinese Hacktool Set - file caidao.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Pass,Config,n{)" fullword ascii
		$s2 = "phMYSQLZ" fullword ascii
		$s3 = "\\DHLP\\." fullword ascii
		$s4 = "\\dhlp\\." fullword ascii
		$s5 = "SHAutoComple" fullword ascii
		$s6 = "MainFrame" ascii

	condition:
		uint16(0)==0x5a4d and filesize <1077KB and all of them
}
