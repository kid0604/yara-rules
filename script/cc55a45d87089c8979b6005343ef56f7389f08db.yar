rule APT_APT29_sorefang_directory_enumeration_output_strings
{
	meta:
		description = "Rule to detect SoreFang based on formatted string output for directory enumeration"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$ = "----------All usres directory----------"
		$ = "----------Desktop directory----------"
		$ = "----------Documents directory----------"

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and 2 of them
}
