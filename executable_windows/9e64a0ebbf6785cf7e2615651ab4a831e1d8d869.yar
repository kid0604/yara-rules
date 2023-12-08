rule MarathonTool_2
{
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"
		os = "windows"
		filetype = "executable"

	strings:
		$s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
		$s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
