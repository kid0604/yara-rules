rule APT_APT29_sorefang_disk_enumeration_strings
{
	meta:
		description = "Rule to detect SoreFang based on disk enumeration strings"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "a4b790ddffb3d2e6691dcacae08fb0bfa1ae56b6c73d70688b097ffa831af064"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\x0D\x0AFree on disk: "
		$ = "Total disk: "
		$ = "Error in GetDiskFreeSpaceEx\x0D\x0A"
		$ = "\x0D\x0AVolume label: "
		$ = "Serial number: "
		$ = "File system: "
		$ = "Error in GetVolumeInformation\x0D\x0A"
		$ = "I can not het information about this disk\x0D\x0A"

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of them
}
