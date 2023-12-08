import "pe"
import "math"

rule HasOverlay : PECheck
{
	meta:
		author = "_pusher_"
		description = "Overlay Check"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)< filesize
}
