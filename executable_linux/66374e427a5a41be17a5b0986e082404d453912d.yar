import "pe"

rule MALWARE_Linux_UNK01
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown/unidentified Linux malware"
		os = "linux"
		filetype = "executable"

	strings:
		$f1 = "%sresponse.php?status" ascii
		$f2 = "%supstream.php?mid=%s&os=%s" ascii fullword
		$f3 = "%supstream.php?tid=%" ascii
		$f4 = "%sindex.php?token=%.32s&flag=%d&name=%s" ascii fullword
		$f5 = "%sactive_off.php?id=%d&uniqu=%d" ascii fullword
		$s1 = "lock:%i usable num:%i n:%i" fullword ascii
		$s2 = "tid:%.*s tNumber:%i" fullword ascii
		$s3 = "init.php" fullword ascii
		$s4 = "mod_drone" fullword ascii
		$s5 = "new_mid" fullword ascii
		$s6 = "&exists[]=" fullword ascii
		$s7 = "&mod[]=" fullword ascii
		$s8 = "shutdown" fullword ascii
		$s9 = "&mac[]=%02X%02X%02X%02X%02X%02X" fullword ascii

	condition:
		uint16(0)==0x457f and (3 of ($f*) or 6 of ($s*))
}
