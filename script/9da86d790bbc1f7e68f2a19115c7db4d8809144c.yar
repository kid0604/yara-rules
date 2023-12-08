rule Batch_Powershell_Invoke_Inveigh
{
	meta:
		author = "NCSC"
		description = "Detects malicious batch file from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "0a6b1b29496d4514f6485e78680ec4cd0296ef4d21862d8bf363900a4f8e3fd2"
		os = "windows"
		filetype = "script"

	strings:
		$ = "Inveigh.ps1" ascii
		$ = "Invoke-Inveigh" ascii
		$ = "-LLMNR N -HTTP N -FileOutput Y" ascii
		$ = "powershell.exe" ascii

	condition:
		all of them
}
