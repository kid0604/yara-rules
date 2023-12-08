rule SUSP_Two_Byte_XOR_PE_And_MZ
{
	meta:
		author = "Wesley Shields <wxs@atarininja.org>"
		description = "Look for 2 byte xor of a PE starting at offset 0"
		reference = "https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83"
		score = 70
		date = "2021-10-11"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)!=0x5a4d and uint32(( uint16(0x3c)^( uint16(0)^0x5a4d))|(( uint16(0x3e)^( uint16(0)^0x5a4d))<<16))^(( uint16(0)^0x5a4d)|(( uint16(0)^0x5a4d)<<16))==0x00004550
}
