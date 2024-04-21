rule case_19438_files_MalFiles_ntds
{
	meta:
		description = "19438 - file ntds.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "060e9ff09cd97ec6a1b614dcc1de50f4d669154f59d78df36e2c4972c2535714"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\\ProgramData\\ntdsutil' q q\"" fullword ascii

	condition:
		uint16(0)==0x6f70 and filesize <1KB and all of them
}
