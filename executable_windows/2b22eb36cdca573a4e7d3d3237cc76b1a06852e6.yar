rule Sword1_5
{
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
		os = "windows"
		filetype = "executable"

	strings:
		$s3 = "http://www.ip138.com/ip2city.asp" fullword wide
		$s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s6 = "ListBox_Command" fullword wide
		$s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
		$s18 = "\\Set.ini" fullword wide
		$s19 = "OpenFileDialog1" fullword wide
		$s20 = " (*.txt)|*.txt" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 4 of them
}
