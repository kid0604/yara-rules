rule CN_Tools_MyUPnP
{
	meta:
		description = "Chinese Hacktool Set - file MyUPnP.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "<description>BYTELINKER.COM</description>" fullword ascii
		$s2 = "myupnp.exe" fullword ascii
		$s3 = "LOADER ERROR" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1500KB and all of them
}
