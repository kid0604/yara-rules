rule whosthere_alt_pth : Toolkit
{
	meta:
		description = "Auto-generated rule - file pth.dll"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "fbfc8e1bc69348721f06e96ff76ae92f3551f33ed3868808efdb670430ae8bd0"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "c:\\debug.txt" fullword ascii
		$s1 = "pth.dll" fullword ascii
		$s2 = "\"Primary\" string found at %.8Xh" fullword ascii
		$s3 = "\"Primary\" string not found!" fullword ascii
		$s4 = "segment 1 found at %.8Xh" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and 4 of them
}
