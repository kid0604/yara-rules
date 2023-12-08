import "pe"

rule APT_MAL_LNX_Turla_Apr20_1
{
	meta:
		description = "Detects Turla Linux malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/Int2e_/status/1246115636331319309"
		date = "2020-04-05"
		hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "/root/.hsperfdata" ascii fullword
		$s2 = "Desc|     Filename     |  size  |state|" ascii fullword
		$s3 = "IPv6 address %s not supported" ascii fullword
		$s4 = "File already exist on remote filesystem !" ascii fullword
		$s5 = "/tmp/.sync.pid" ascii fullword
		$s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword

	condition:
		uint16(0)==0x457f and filesize <5000KB and 4 of them
}
