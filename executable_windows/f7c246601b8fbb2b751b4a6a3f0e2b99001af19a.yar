import "math"
import "pe"

rule IsBeyondImageSize : PECheck
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "Data Beyond ImageSize Check"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and for any i in (0..pe.number_of_sections-1) : ((pe.sections[i].virtual_address+pe.sections[i].virtual_size)>( uint32( uint32(0x3C)+0x50)) or (pe.sections[i].raw_data_offset+pe.sections[i].raw_data_size)> filesize )
}
