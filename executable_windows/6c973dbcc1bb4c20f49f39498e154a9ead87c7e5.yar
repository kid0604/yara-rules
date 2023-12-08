rule Arp_EMP_v1_0
{
	meta:
		description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Arp EMP v1.0.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
