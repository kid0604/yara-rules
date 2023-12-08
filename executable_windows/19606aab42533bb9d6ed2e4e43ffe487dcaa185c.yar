import "pe"

rule MALWARE_Win_CryLock
{
	meta:
		author = "ditekSHen"
		description = "Detects CryLock ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Encrypted by BlackRabbit. (BR-" ascii
		$s2 = "{ENCRYPTENDED}" ascii
		$s3 = "{ENCRYPTSTART}" ascii
		$s4 = "<%UNDECRYPT_DATETIME%>" ascii
		$s5 = "<%RESERVE_CONTACT%>" ascii
		$s6 = "how_to_decrypt.hta" ascii wide
		$s7 = "END ENCRYPT ONLY EXTENATIONS" ascii
		$s8 = "END UNENCRYPT EXTENATIONS" ascii
		$s9 = "END COMMANDS LIST" ascii
		$s10 = "END PROCESSES KILL LIST" ascii
		$s11 = "END SERVICES STOP LIST" ascii
		$s12 = "END PROCESSES WHITE LIST" ascii
		$s13 = "END UNENCRYPT FILES LIST" ascii
		$s14 = "END UNENCRYPT FOLDERS LIST" ascii
		$s15 = "Encrypted files:" ascii
		$s16 = { 65 78 74 65 6e 61 74 69 6f 6e 73 00 ff ff ff ff
                 06 00 00 00 63 6f 6e 66 69 67 00 00 ff ff ff ff
                 (0a|0d 0a) 00 00 00 63 6f 6e 66 69 67 2e 74 78 
                 74 00 00 ff ff ff ff 03 00 00 00 68 74 61 }
		$p1 = "-exclude" fullword
		$p2 = "-makeff" fullword
		$p3 = "-full" fullword
		$p4 = "-nolocal" fullword
		$p5 = "-nolan" fullword
		$p6 = "\" -id \"" fullword
		$p7 = "\" -wid \"" fullword
		$p8 = "\"runas\"" fullword
		$p9 = " -f -s -t 00" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) or 6 of ($p*))
}
