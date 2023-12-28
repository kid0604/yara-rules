rule BlackTech_PLEAD_dummycode
{
	meta:
		description = "PLEAD malware dummy code in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "d44b38360499cfc6c892b172707e3ea6e72605ad365994ee31cf6a638e288e8d"
		hash2 = "c825c7e575c97bf7280788147bd00dba732e333266f20eb38bce294d9bff238a"
		os = "windows"
		filetype = "script"

	strings:
		$dummy1 = "test-%d"
		$dummy2 = "test.ini"
		$dummy3 = "ShellClassInfo.txt"
		$dummy4 = "desktop.ini"
		$dummy5 = "%02d%02d%02d"
		$dummy6 = "%s-%02d-%02d-%02d"

	condition:
		4 of ($dummy*)
}
