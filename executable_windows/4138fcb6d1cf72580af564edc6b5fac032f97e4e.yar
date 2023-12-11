rule APT_APT29_sorefang_add_random_commas_spaces
{
	meta:
		description = "Rule to detect SoreFang based on function that adds commas and spaces"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 8B CE 83 FA 04 7E 09 6A
            02 68 ?? ?? ?? ?? EB 07 6A 01 68 }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}
