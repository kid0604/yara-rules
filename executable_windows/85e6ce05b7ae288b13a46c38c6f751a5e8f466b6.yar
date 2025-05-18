rule APT10_ANEL_dll
{
	meta:
		description = "ANEL loader dll"
		author = "JPCERT/CC Incident Response Group"
		hash = "ad81f5ca47f250198afeed733abde459fb83447f1a77d5fcb1548af387643b54"
		os = "windows"
		filetype = "executable"

	strings:
		$text_b = {3c 3e 44 3e 4c 3e 54 3e 5c 3e 64 3e 6c 3e 74 3e}
		$text_s = "hprOBnaeloheSredDyrctbuo"

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3c))==0x00004550 and filesize <1000KB and all of them
}
