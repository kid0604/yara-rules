import "pe"

rule MALWARE_Win_RaccoonV2
{
	meta:
		author = "ditekSHen"
		description = "Detects Raccoon Stealer 2.0, also referred to as RecordBreaker"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "sgnl_" fullword ascii
		$f2 = "tlgrm_" fullword ascii
		$f3 = "ews_" fullword ascii
		$f4 = "grbr_" fullword ascii
		$f5 = "dscrd_" fullword ascii
		$f6 = "wlts_" fullword ascii
		$f7 = "scrnsht_" fullword ascii
		$f8 = "sstmnfo_" fullword ascii
		$s1 = "machineId=" fullword ascii
		$s2 = "&configId=" fullword ascii
		$s3 = "URL:%s" fullword ascii
		$s4 = "USR:%s" fullword ascii
		$s5 = "PASS:%s" fullword ascii
		$s6 = "Content-Type: application/x-object" fullword ascii

	condition:
		(( uint16(0)==0x5a4d and (4 of ($f*) or all of ($s*) or 7 of them )) or 10 of them )
}
