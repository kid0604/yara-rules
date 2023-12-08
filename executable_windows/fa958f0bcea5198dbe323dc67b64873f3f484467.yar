rule APT_MAL_CISA_10365227_01_APPSTORAGE_Dec21
{
	meta:
		author = "CISA Code & Media Analysis"
		date = "2021-12-23"
		modified = "2021-12-24"
		family = "APPSTORAGE"
		score = 80
		description = "Detects AppStorage ntstatus msexch samples"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		hash1 = "157a0ffd18e05bfd90a4ec108e5458cbde01015e3407b3964732c9d4ceb71656"
		hash2 = "30191b3badf3cdbc65d0ffeb68e0f26cef10a41037351b0f562ab52fce7432cc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "026B924DD52F8BE4A3FEE8575DC"
		$s2 = "GetHDDId"
		$s3 = "AppStorage"
		$s4 = "AppDomain"
		$s5 = "$1e3e5580-d264-4c30-89c9-8933c948582c"
		$s6 = "hrjio2mfsdlf235d" wide

	condition:
		uint16(0)==0x5a4d and all of them
}
