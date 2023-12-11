rule APT_MAL_CISA_10365227_03_ClientUploader_Dec21
{
	meta:
		author = "CISA Code & Media Analysis"
		date = "2021-12-23"
		modified = "2021-12-24"
		score = 80
		description = "Detects ClientUploader onedrv"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		hash1 = "84164e1e8074c2565d3cd178babd93694ce54811641a77ffdc8d1084dd468afb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Decoder2"
		$s2 = "ClientUploader"
		$s3 = "AppDomain"
		$s4 = { 5F 49 73 52 65 70 47 ?? 44 65 63 6F 64 65 72 73 }
		$s5 = "LzmaDecoder"
		$s6 = "$ee1b3f3b-b13c-432e-a461-e52d273896a7"

	condition:
		uint16(0)==0x5a4d and all of them
}
