rule case_19438_files_MalFiles_start
{
	meta:
		description = "19438 - file start.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "4c0736c9a19c2e172bb504556f7006fa547093b79a0a7e170e6412f98137e7cd"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "pingcastle.exe --healthcheck --level Full > process.log 2>&1" fullword ascii
		$s2 = "cd C:\\ProgramData\\" fullword ascii

	condition:
		uint16(0)==0x6463 and filesize <1KB and all of them
}
