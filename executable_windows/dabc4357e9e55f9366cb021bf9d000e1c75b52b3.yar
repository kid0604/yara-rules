rule APT_APT29_sorefang_encryption_round_function
{
	meta:
		description = "Rule to detect SoreFang based on the encryption round function"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 8A E9 8A FB 8A 5D 0F 02 C9 88 45 0F FE C1 0F BE C5 88 6D F3 8D
            14 45 01 00 00 00 0F AF D0 0F BE C5 0F BE C9 0F AF C8 C1 FA 1B C0 E1 05 0A D1 8B 4D EC 0F BE C1 89 55 E4 8D 14 45 01 00 00 00 0F AF D0 8B C1}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}
