import "pe"

rule MALWARE_Win_IAmTheKingKeylogger
{
	meta:
		author = "ditekSHen"
		description = "IAmTheKing Keylogger payload"
		clamav_sig = "MALWARE.Win.Trojan.IAmTheKingKeylogger"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[TIME:]%d/%d/%d %02d:%02d:%02d" fullword ascii
		$s2 = "[TITLE:]" fullword ascii
		$s3 = "%s-%02d-%02d-%02d-%02d" fullword ascii
		$s4 = "[DATA]:" fullword ascii
		$s5 = "[BK]" fullword ascii
		$s6 = "Log.txt" fullword ascii
		$s7 = "sonme hting is wrong x" fullword ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
