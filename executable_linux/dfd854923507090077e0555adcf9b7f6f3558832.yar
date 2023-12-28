rule upx_antiunpack_elf32
{
	meta:
		description = "UPX Anti-Unpacking technique to magic renamed for ELF32"
		author = "JPCERT/CC Incident Response Group"
		os = "linux"
		filetype = "executable"

	condition:
		uint32(0)==0x464C457F and uint8(4)==1 and (( for any magic in ( uint32( filesize -0x24)) : (magic== uint32( uint16(0x2C)* uint16(0x2A)+ uint16(0x28)+4)) and not for any magic in (0x21585055,0) : (magic== uint32( uint16(0x2C)* uint16(0x2A)+ uint16(0x28)+4)) and uint32( uint16(0x2C)* uint16(0x2A)+ uint16(0x28)+4)>0x0000FFFF) or ( for any magic in ( uint32( filesize -0x24)) : (magic== uint32( uint16be(0x2C)* uint16be(0x2A)+ uint16be(0x28)+4)) and not for any magic in (0x21585055,0) : (magic== uint32( uint16be(0x2C)* uint16be(0x2A)+ uint16be(0x28)+4)) and uint32( uint16be(0x2C)* uint16be(0x2A)+ uint16be(0x28)+4)>0x0000FFFF))
}
