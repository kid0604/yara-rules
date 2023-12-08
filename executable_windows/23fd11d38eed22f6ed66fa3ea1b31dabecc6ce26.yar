rule MAL_QakBotLoader_Export_Section_Feb23
{
	meta:
		author = "kevoreilly"
		description = "QakBot Export Selection"
		cape_options = "export=$export"
		hash = "6f99171c95a8ed5d056eeb9234dbbee123a6f95f481ad0e0a966abd2844f0e1a"
		reference = "https://github.com/kevoreilly/CAPEv2/blob/master/analyzer/windows/data/yara/QakBot.yar"
		date = "2023-02-17"
		license = "https://github.com/kevoreilly/CAPEv2/blob/master/LICENSE"
		os = "windows"
		filetype = "executable"

	strings:
		$export = {55 8B EC 83 EC 50 (3A|66 3B) ?? 74}
		$wind = {(66 3B|3A) ?? 74 [1-14] BB 69 04 00 00 53 E8 [5-7] 74}

	condition:
		uint16(0)==0x5A4D and all of them
}
