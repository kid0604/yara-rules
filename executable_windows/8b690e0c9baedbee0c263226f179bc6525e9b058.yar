rule APT_Malware_PutterPanda_Gen1
{
	meta:
		description = "Detects a malware "
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "bf1d385e637326a63c4d2f253dc211e6a5436b6a"
		hash1 = "76459bcbe072f9c29bb9703bc72c7cd46a692796"
		hash2 = "e105a7a3a011275002aec4b930c722e6a7ef52ad"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s%duserid=%dthreadid=%dgroupid=%d" fullword ascii
		$s2 = "ssdpsvc.dll" fullword ascii
		$s3 = "Fail %s " fullword ascii
		$s4 = "%s%dpara1=%dpara2=%dpara3=%d" fullword ascii
		$s5 = "LsaServiceInit" fullword ascii
		$s6 = "%-8d Fs %-12s Bs " fullword ascii
		$s7 = "Microsoft DH SChannel Cryptographic Provider" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 5 of them
}
