rule APT_MAL_CISA_10365227_02_ClientUploader_Dec21
{
	meta:
		author = "CISA Code & Media Analysis"
		date = "2021-12-23"
		modified = "2021-12-24"
		score = 80
		description = "Detects ClientUploader_mqsvn"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		hash1 = "3585c3136686d7d48e53c21be61bb2908d131cf81b826acf578b67bb9d8e9350"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UploadSmallFileWithStopWatch"
		$s2 = "UploadPartWithStopwatch"
		$s3 = "AppVClient"
		$s4 = "ClientUploader"
		$s5 = { 46 69 6C 65 43 6F 6E 74 61 69 6E 65 72 2E 46 69 6C 65 41 72 63 68 69 76 65 }
		$s6 = { 4F 6E 65 44 72 69 76 65 43 6C 69 65 6E 74 2E 4F 6E 65 44 72 69 76 65 }

	condition:
		uint16(0)==0x5a4d and all of them
}
