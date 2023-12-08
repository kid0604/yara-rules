rule Akira
{
	meta:
		author = "rivitna"
		family = "ransomware.akira.windows"
		description = "Akira ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\x00--encryption_path\x00" ascii
		$s1 = "\x00--share_file\x00" ascii
		$s2 = "\x00--encryption_percent\x00" ascii
		$s3 = "\x00-fork\x00" ascii
		$s4 = "\x00Failed to read share files\x00" ascii
		$s5 = ":\\akira\\asio\\include\\" ascii
		$s6 = "\x00write_encrypt_info error: \x00" ascii
		$s7 = "\x00encrypt_part error: \x00" ascii
		$s8 = "\x00Detected number of cpus = \x00" ascii
		$s9 = "\x00No path to encrypt\x00" ascii
		$s10 = "Paste this link - https://akira" ascii
		$s11 = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA" ascii
		$s12 = "\x00Trend Micro\x00" wide
		$s13 = " :Failed to make full encrypt\x00" wide
		$s14 = " :Failed to make spot encrypt\x00" wide
		$s15 = " :Failed to make part encrypt\x00" wide
		$s16 = " :Failed to write header\x00" wide
		$s17 = " :file rename failed. System error: \x00" wide
		$h0 = { 41 BA 05 00 00 00 41 80 FB 32 44 0F 42 D0 33 D2 48 8B C?
                49 F7 F2 4C 8B C8 B9 02 00 00 00 41 B8 04 00 00 00
                41 80 FB 32 44 0F 42 C1 41 8B C8 48 0F AF C8 48 2B F9 33 D2
                48 8B C7 49 F7 F2 }
		$h1 = { C7 45 ?? 03 00 00 00 80 7D ?? 31 76 07 C7 45 ?? 05 00 00 00
                0F B6 45 ?? 48 0F AF 45 ?? 48 C1 E8 02
                48 B? C3 F5 28 5C 8F C2 F5 28 48 F7 E? 48 89 ?? 48 C1 E8 02 }

	condition:
		((( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) or ( uint32(0)==0x464C457F)) and ((7 of ($s*)) or (1 of ($h*)))
}
