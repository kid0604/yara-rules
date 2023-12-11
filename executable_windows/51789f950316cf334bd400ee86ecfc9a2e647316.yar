rule memdump_diablo
{
	meta:
		author = "@patrickrolsen"
		reference = "Process Memory Dumper - DiabloHorn"
		description = "Yara rule for detecting the presence of the Process Memory Dumper tool - DiabloHorn"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DiabloHorn"
		$s2 = "Process Memory Dumper"
		$s3 = "pid-%s.dmp"
		$s4 = "Pid %d in not acessible"
		$s5 = "memdump.exe"
		$s6 = "%s-%d.dmp"

	condition:
		uint16(0)==0x5A4D and 3 of ($s*)
}
