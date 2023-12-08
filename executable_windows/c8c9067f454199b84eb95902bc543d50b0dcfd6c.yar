rule Nanocore_RAT_Gen_2
{
	meta:
		description = "Detetcs the Nanocore RAT"
		author = "Florian Roth"
		score = 100
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		hash1 = "755f49a4ffef5b1b62f4b5a5de279868c0c1766b528648febf76628f1fe39050"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "NanoCore.ClientPluginHost" fullword ascii
		$x2 = "IClientNetworkHost" fullword ascii
		$x3 = "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 1 of them ) or ( all of them )
}
