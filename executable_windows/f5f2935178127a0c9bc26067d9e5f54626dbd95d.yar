rule Nautilus_common_strings
{
	meta:
		description = "Rule for detection of Nautilus based on common plaintext strings"
		author = "NCSC UK"
		hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
		date = "2017/11/23"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "nautilus-service.dll" ascii
		$ = "oxygen.dll" ascii
		$ = "config_listen.system" ascii
		$ = "ctx.system" ascii
		$ = "3FDA3998-BEF5-426D-82D8-1A71F29ADDC3" ascii
		$ = "C:\\ProgramData\\Microsoft\\Windows\\Caches\\{%s}.2.ver0x0000000000000001.db" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and 3 of them
}
