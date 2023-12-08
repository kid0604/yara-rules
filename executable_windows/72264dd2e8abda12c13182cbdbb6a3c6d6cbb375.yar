rule APT30_Generic_5
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "cb4833220c508182c0ccd4e0d5a867d6c4e675f8"
		hash1 = "dfc9a87df2d585c479ab02602133934b055d156f"
		hash2 = "bf59d5ff7d38ec5ffb91296e002e8742baf24db5"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "regsvr32 /s \"%ProgramFiles%\\Norton360\\Engine\\5.1.0.29\\ashelper.dll\"" fullword
		$s1 = "name=\"ftpserver.exe\"/>" fullword
		$s2 = "LiveUpdate.EXE" fullword wide
		$s3 = "<description>FTP Explorer</description>" fullword
		$s4 = "\\ashelper.dll"
		$s5 = "LiveUpdate" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
