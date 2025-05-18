import "pe"

rule MAL_APT_NK_Andariel_NoPineapple_Dtrack_Unpacked
{
	meta:
		author = "CISA.gov"
		description = "Detects the Dtrack variant used by Andariel"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		date = "2024-07-25"
		score = 80
		id = "6ccaf24b-c110-5788-a792-fa7f39fb18f7"
		os = "windows"
		filetype = "executable"

	strings:
		$str_nopineapple = "< No Pineapple! >"
		$str_qt_library = "Qt 5.12.10"
		$str_xor = {8B 10 83 F6 ?? 83 FA 01 77}

	condition:
		uint16(0)==0x5A4D and all of them
}
