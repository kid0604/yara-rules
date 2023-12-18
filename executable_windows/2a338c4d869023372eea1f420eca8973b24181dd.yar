rule MAL_DLL_Stealer_Nov23
{
	meta:
		author = "X__Junior"
		description = "Detects a DLL that steals authentication credentials - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
		date = "2023-11-23"
		hash1 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"
		score = 80
		id = "9cfed8ec-1d04-53d7-88ef-2576075cfc33"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { C7 45 ?? 4D 69 6E 69 C7 45 ?? 44 75 6D 70 C7 45 ?? 57 72 69 74 C7 45 ?? 65 44 75 6D C7 45 ?? 70 00 27 00 C7 45 ?? 44 00 62 00 C7 45 ?? 67 00 68 00 C7 45 ?? 65 00 6C 00 C7 45 ?? 70 00 2E 00 C7 45 ?? 64 00 6C 00 C7 45 ?? 6C 00 00 00}

	condition:
		uint16(0)==0x5a4d and all of them
}
