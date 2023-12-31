rule upx_antiunpack_elf64
{
	meta:
		description = "UPX Anti-Unpacking technique to magic renamed for ELF64"
		author = "JPCERT/CC Incident Response Group"
		os = "linux"
		filetype = "executable"

	condition:
		uint32(0)==0x464C457F and uint8(4)==2 and (( for any magic in ( uint32( filesize -0x24)) : (magic== uint32( uint16(0x36)* uint16(0x38)+ uint16(0x34)+4)) and not for any magic in (0x21585055,0) : (magic== uint32( uint16(0x36)* uint16(0x38)+ uint16(0x34)+4)) and uint32( uint16(0x36)* uint16(0x38)+ uint16(0x34)+4)>0x000000FF) or ( for any magic in ( uint32( filesize -0x24)) : (magic== uint32( uint16be(0x36)* uint16be(0x38)+ uint16be(0x34)+4)) and not for any magic in (0x21585055,0) : (magic== uint32( uint16be(0x36)* uint16be(0x38)+ uint16be(0x34)+4)) and uint32( uint16be(0x36)* uint16be(0x38)+ uint16be(0x34)+4)>0x000000FF))
}
