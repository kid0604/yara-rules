rule APT_APT29_sorefang_command_elem_cookie_ga_boundary_string
{
	meta:
		description = "Rule to detect SoreFang based on scheduled task element and Cookie header/boundary strings"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "<Command>" wide
		$ = "Cookie:_ga="
		$ = "------974767299852498929531610575"

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and 2 of them
}
