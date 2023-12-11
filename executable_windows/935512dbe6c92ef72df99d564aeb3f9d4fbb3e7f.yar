rule Molerats_Jul17_Sample_2
{
	meta:
		description = "Detects Molerats sample - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "7e122a882d625f4ccac019efb7bf1b1024b9e0919d205105e7e299fb1a20a326"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Folder.exe" fullword ascii
		$s2 = "Notepad++.exe" fullword wide
		$s3 = "RSJLRSJOMSJ" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
