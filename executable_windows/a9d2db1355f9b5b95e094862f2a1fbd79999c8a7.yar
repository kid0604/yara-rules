rule kelloworld_2
{
	meta:
		description = "Chinese Hacktool Set - file kelloworld.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Hello World!" fullword wide
		$s2 = "kelloworld.dll" fullword ascii
		$s3 = "kelloworld de mimikatz pour Windows" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
