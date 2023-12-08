rule RemoteExec_Tool
{
	meta:
		description = "Remote Access Tool used in APT Terracotta"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		hash = "a550131e106ff3c703666f15d55d9bc8c816d1cb9ac1b73c2e29f8aa01e53b78"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "cmd.exe /q /c \"%s\"" fullword ascii
		$s1 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s2 = "This is a service executable! Couldn't start directly." fullword ascii
		$s3 = "\\\\.\\pipe\\TermHlp_communicaton" fullword ascii
		$s4 = "TermHlp_stdout" fullword ascii
		$s5 = "TermHlp_stdin" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <75KB and 4 of ($s*)
}
