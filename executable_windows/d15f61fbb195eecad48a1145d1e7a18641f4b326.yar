rule hscangui
{
	meta:
		description = "Chinese Hacktool Set - file hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "af8aced0a78e1181f4c307c78402481a589f8d07"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "http://www.cnhonker.com" fullword ascii
		$s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
		$s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <220KB and 2 of them
}
