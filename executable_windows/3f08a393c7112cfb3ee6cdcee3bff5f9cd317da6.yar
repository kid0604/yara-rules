rule SunCrypt
{
	meta:
		author = "rivitna"
		family = "ransomware.suncrypt.windows"
		description = "SunCrypt ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { B0 00 02 00 C7 00 A3 00 00 00 [8-16] 83 C? 20 }
		$h1 = { C7 00 A3 00 00 00 [8-16]
                ( 81 C7 B0 00 02 00 83 C? 20 | 83 C? 20 81 C7 B0 00 02 00) }
		$s1 = "-noshares\x00" wide
		$s2 = "\x00-nomutex\x00" wide
		$s3 = "\x00-noreport\x00" wide
		$s4 = "\x00-noservices\x00" wide
		$s5 = "\x00-justcrypt\x00" wide
		$s6 = "\x00-keep_exe\x00" wide
		$s7 = "\x00$Recycle.bin\x00" wide
		$s8 = "%s\\efi\\microsoft\\boot\\bootmgr.efi\x00" wide
		$s9 = "YOUR_FILES_ARE_ENCRYPTED.HTML\x00" wide
		$s10 = "\x0D... %d ...\x00" ascii
		$a1 = "<a href=\"http://" ascii xor(0x11-0x22)
		$a2 = ".onion/chat.html?" ascii xor(0x11-0x22)
		$a3 = "<h2>Why pay us?</h2>" ascii xor(0x11-0x22)
		$a4 = "background-color: #1a1a1a;" ascii xor(0x11-0x22)
		$a5 = "rem !important;" ascii xor(0x11-0x22)
		$a6 = "TOR browser" ascii xor(0x11-0x22)
		$a7 = "torproject.org" ascii xor(0x11-0x22)

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((1 of ($h*)) or (5 of ($s*)) or (4 of ($a*)))
}
