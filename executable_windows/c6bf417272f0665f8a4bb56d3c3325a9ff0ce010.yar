rule case_19772_svchost_nokoyawa_ransomware
{
	meta:
		description = "19772 - file svchost.exe"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion"
		date = "2024-01-09"
		hash1 = "3c9f4145e310f616bd5e36ca177a3f370edc13cf2d54bb87fe99972ecf3f09b4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = " ;3;!X" fullword ascii
		$s2 = "bcdedit" fullword wide
		$s3 = "geKpgAX3" fullword ascii
		$s4 = "shutdown" fullword wide
		$s5 = "k2mm7KvHl51n2LJDYLanAgM48OX97gkV" fullword ascii
		$s6 = "+TDPbuWCWNmcW0k=" fullword ascii
		$s7 = "4vEBlUlgJ5oeqmbpb9OSaQrQb8bRWNqP" fullword ascii
		$s8 = "2aDXUPxh3ZZ1x8tpfg6PxcMuUwWogOgQ" fullword ascii
		$s9 = "kfeCWydRqz8=" fullword ascii
		$s10 = "ZfrMxxDy" fullword ascii
		$s11 = "eLTuGYHd" fullword ascii
		$s12 = "wWIQZ5jJPZIiuDKxQVh0YO3HnzdOwirY" fullword ascii
		$s13 = "+IdWS+zG9rUG" fullword ascii
		$s14 = "0ZdUoZmp" fullword ascii
		$s15 = "SVWh$l@" fullword ascii
		$s16 = "Z2mJzxHFaRafgf4k/uTdeMKIMUpV/y81" fullword ascii
		$s17 = "GtKqGSOfNUOVIoMTk8bGZVchMddKIuTN" fullword ascii
		$s18 = "INMvjo3GzuQ6MTSJUg==" fullword ascii
		$s19 = "hilWGBcFwE80e5L9BXxCiRiE" fullword ascii
		$s20 = "gSMSrcOR" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <70KB and 8 of them
}
