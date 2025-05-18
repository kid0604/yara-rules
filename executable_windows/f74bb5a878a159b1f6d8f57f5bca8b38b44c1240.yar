import "pe"

rule MAL_APT_NK_Andariel_GoLang_Validalpha_BlackString
{
	meta:
		author = "CISA.gov"
		description = "Detects a variant of the GoLang Validalpha malware based on a file path found in the samples"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		date = "2024-07-25"
		score = 90
		id = "36f46a1d-69b6-5c99-9a54-6a14d62d2721"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "I:/01___Tools/02__RAT/Black"

	condition:
		uint16(0)==0x5A4D and all of them
}
