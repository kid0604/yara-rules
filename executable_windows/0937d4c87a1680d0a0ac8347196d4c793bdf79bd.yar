rule BlueLocker
{
	meta:
		author = "rivitna"
		family = "ransomware.bluelocker"
		description = "BlueLocker ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { 0F 8F ?? 01 00 00 3D 00 00 A0 00 0F 82 ?? 01 00 00
                85 C? 0F 8F ?? 01 00 00 7C 0B 3D 00 00 ( 20 03 | 40 06)
                0F 83 ?? 01 00 00 }
		$s0 = "wbizecif48njqgpprzkm6769" ascii wide
		$s1 = "\x00Bule Cryptor\x00" ascii wide
		$s2 = "\x00.blue\x00" ascii wide
		$s3 = "\x00restore_file.txt\x00" ascii wide
		$s4 = "wmic SHADOWCOPY DELETE" ascii wide fullword
		$s5 = " LOCKER****" ascii
		$s6 = "[ Hello! ]" ascii
		$s7 = "!!! DANGER !!!" ascii

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((1 of ($h*)) or (4 of ($s*)))
}
