rule whosthere_alt_1 : Toolkit
{
	meta:
		description = "Auto-generated rule - file whosthere.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "d7a82204d3e511cf5af58eabdd6e9757c5dd243f9aca3999dc0e5d1603b1fa37"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii
		$s2 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii
		$s3 = "specify addresses to use. Format: ADDCREDENTIAL_ADDR:ENCRYPTMEMORY_ADDR:FEEDBACK_ADDR:DESKEY_ADDR:LOGONSESSIONLIST_ADDR:LOGONSES" ascii
		$s4 = "Could not enable debug privileges. You must run this tool with an account with administrator privileges." fullword ascii
		$s5 = "-B is now used by default. Trying to find correct addresses.." fullword ascii
		$s6 = "Cannot get LSASS.EXE PID!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <320KB and 2 of them
}
