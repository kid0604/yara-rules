import "pe"

rule MALWARE_Win_FirebirdRAT
{
	meta:
		author = "ditekSHen"
		description = "Firebird/Hive RAT payload"
		clamav_sig = "MALWARE.Win.Trojan.Firebird-HiveRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$id1 = "Firebird Remote Administration Tool" fullword wide
		$id2 = "Welcome to Firebird! Your system is currently being monitored" wide
		$id3 = "Hive Remote Administration Tool" fullword wide
		$id4 = "Welcome to Hive! Your system is currently being monitored" wide
		$s1 = "REPLACETHESEKEYSTROKES" fullword wide
		$s2 = "_ENABLE_PROFILING" fullword wide
		$s3 = ": KeylogSubject" wide
		$s4 = "Firebird.CommandHandler" fullword wide
		$s5 = "webcamenabled" fullword ascii
		$s6 = "screenlogs" fullword ascii
		$s7 = "encryptedconnection" fullword ascii
		$s8 = "monitoron" fullword ascii
		$s9 = "screenGrab" fullword ascii
		$s10 = "TCP_TABLE_OWNER_PID_ALL" fullword ascii
		$s11 = "de4fuckyou" fullword ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($id*) or 7 of ($s*))
}
