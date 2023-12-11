rule Dos_1
{
	meta:
		description = "Chinese Hacktool Set - file 1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
		$s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
