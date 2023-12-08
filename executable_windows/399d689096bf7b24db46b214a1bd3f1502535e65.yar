rule Emdivi_Gen2
{
	meta:
		description = "Detects Emdivi Malware"
		author = "Florian Roth (Nextron Systems) @Cyber0ps"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		modified = "2023-01-27"
		super_rule = 1
		score = 80
		hash1 = "9a351885bf5f6fec466f30021088504d96e9db10309622ed198184294717add1"
		hash2 = "a5be7cb1f37030c9f9211c71e0fbe01dae19ff0e6560c5aab393621f18a7d012"
		hash3 = "9183abb9b639699cd2ad28d375febe1f34c14679b7638d1a79edb49d920524a4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%TEMP%\\IELogs\\" ascii
		$s2 = "MSPUB.EXE" fullword ascii
		$s3 = "%temp%\\" ascii
		$s4 = "\\NOTEPAD.EXE" ascii
		$s5 = "%4d-%02d-%02d %02d:%02d:%02d " fullword ascii
		$s6 = "INTERNET_OPEN_TYPE_PRECONFIG" fullword ascii
		$s7 = "%4d%02d%02d%02d%02d%02d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1300KB and 6 of them
}
