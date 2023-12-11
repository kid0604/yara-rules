rule APT_APT29_sorefang_modify_alphabet_custom_encode
{
	meta:
		description = "Rule to detect SoreFang based on arguments passed into custom encoding algorithm function"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 33 C0 8B CE 6A 36 6A 71 66 89 46 60 88 46 62 89 46 68 66 89 46
            64 }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}
