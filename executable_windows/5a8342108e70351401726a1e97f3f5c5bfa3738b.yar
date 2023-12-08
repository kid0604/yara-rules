import "pe"

private rule WINDOWS_UPDATE_BDC
{
	meta:
		score = 0
		description = "Detects Windows update binary data"
		os = "windows"
		filetype = "executable"

	condition:
		( uint32be(0)==0x44434d01 and uint32be(4)==0x50413330) or ( uint32be(0)==0x44434401 and uint32be(12)==0x50413330)
}
