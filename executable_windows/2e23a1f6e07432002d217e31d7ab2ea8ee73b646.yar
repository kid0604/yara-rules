import "pe"

rule keyboy_init_config_section
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the Init section where the config is stored"
		date = "2016-08-28"
		description = "Matches the Init section where the config is stored"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <300KB and for any i in (0..pe.number_of_sections-1) : (pe.sections[i].name==".Init" and pe.sections[i].virtual_size%1024==0)
}
