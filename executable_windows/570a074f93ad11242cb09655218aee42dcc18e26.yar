rule lamescan3
{
	meta:
		description = "Chinese Hacktool Set - file lamescan3.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "dic\\loginlist.txt" fullword ascii
		$s2 = "Radmin.exe" fullword ascii
		$s3 = "lamescan3.pdf!" fullword ascii
		$s4 = "dic\\passlist.txt" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3740KB and all of them
}
