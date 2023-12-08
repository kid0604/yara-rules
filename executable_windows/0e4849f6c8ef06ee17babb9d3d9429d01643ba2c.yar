rule Inc
{
	meta:
		author = "rivitna"
		family = "ransomware.inc"
		description = "Inc. ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { 6A 00 6A 00 6A 18 8D [3-4] 5? 68 28 C0 53 00 }
		$h1 = { 6A 00 68 80 00 00 00 6A 03 6A 00 6A 03 [0-16] 68 9F 01 12 00
                [0-8] C7 44 24 ?? 2E 00 5C 00 }
		$h2 = { 6A 20 FF 35 [4] FF 15 [8-12] 8A 4? 1F 80 2? F8 24 3F 0C 40
                88 4? 1F }
		$s0 = "\x00Q:\\\x00W:\\\x00E:\\\x00R:\\\x00T:\\\x00Y:\\\x00U:\\" wide
		$s1 = "PGh0bWw+DQoJPGhlYWQ+DQoJCTx0aXRsZT5JbmMuIFJhbnNvbXdhcmU8" ascii
		$s2 = "\\background-image.jpg\x00" wide
		$s3 = "\x00--lhd\x00" wide
		$s4 = "\x00--ens\x00" wide
		$s5 = "\x00--sup\x00" wide
		$s6 = " delete shadow copies from %c:/ " wide
		$s7 = "\x00[+] Start encryption of" wide
		$s8 = "[+] Encrypting: %s\n" wide
		$s9 = "[+] Found drive: %s" wide
		$s10 = "   [+] Mounted %s\n" wide
		$s11 = "   [-] Failed to mount %s Error: %d\n" wide
		$s12 = "[*] Count of arguments: %d\n" wide
		$s13 = "[-] Please, add \"/\" to the end of directory!\n" wide
		$s14 = "[*] Settings:\n" wide
		$s15 = "   [%s] Stop using process\n" wide
		$s16 = "   [%s] Encrypt network shares\n" wide
		$s17 = "   [%s] Load hidden drives\n\n" wide
		$s18 = "[*] Loading hidden drives...\n" wide
		$s19 = "[*] Starting full encryption in 5s" wide
		$s20 = "[+] Start sending note to printers...\n" ascii
		$s21 = "[+] Count of printers: %d\n" ascii

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((7 of ($s*)) or ((1 of ($h*)) and (3 of ($s*))))
}
