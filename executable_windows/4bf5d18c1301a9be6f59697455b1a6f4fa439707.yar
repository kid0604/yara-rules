rule MAL_CRIME_Unknown_LNK_Jun21_1 : LNK POWERSHELL
{
	meta:
		author = "Nils Kuhnert"
		date = "2021-06-04"
		description = "Triggers on malicious link files which calls powershell with an obfuscated payload and downloads an HTA file."
		hash1 = "8fc7f25da954adcb8f91d5b0e1967e4a90ca132b280aa6ae73e150b55d301942"
		hash2 = "f5da192f4e4dfb6b728aee1821d10bec6d68fb21266ce32b688e8cae7898a522"
		hash3 = "183a9b3c04d16a1822c788d7a6e78943790ee2cdeea12a38e540281091316e45"
		hash4 = "a38c6aa3e1c429a27226519b38f39f03b0b1b9d75fd43cd7e067c5e542967afe"
		hash5 = "455f7b6b975fb8f7afc6295ec40dae5696f5063d1651f3b2477f10976a3b67b2"
		os = "windows"
		filetype = "executable"

	strings:
		$uid = "S-1-5-21-1437133880-1006698037-385855442-1004" wide

	condition:
		uint16(0)==0x004c and all of them
}
