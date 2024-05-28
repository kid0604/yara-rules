rule Trinity_alt_2
{
	meta:
		author = "rivitna"
		family = "ransomware.trinity.windows"
		description = "Trinity ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\x00pbsecGOOD\x00" ascii
		$s1 = "\x00secpbGOOD\x00" ascii
		$s2 = "12210111111610599117115" ascii
		$s3 = "\x00OnlyCr :\x00" ascii
		$s4 = "\x00FullCr :\x00" ascii
		$s5 = "\x00enableOnlyTest \x00" ascii
		$s6 = "\x00EnableAutoStart \x00" ascii
		$s7 = "\x00enableSelfDelete \x00" ascii
		$s8 = "\x00enableStartOnRun \x00" ascii
		$s9 = "\x00enableWallaper \x00" ascii
		$s10 = "\x00enableNetwork \x00" ascii
		$s11 = "\x00enableCustomCMD1 \x00" ascii
		$s12 = "\x00enableFullEncrExt \x00" ascii
		$s13 = "\x00enableCryptOnlyExtension \x00" ascii
		$s14 = "\x00enableCryptOnlyExtension \x00" ascii
		$s15 = "\x00%s%x%x%x%x.goodgame\x00" wide
		$h0 = { B? 01 00 00 00 33 ?? 0F B6 [10] C1 E? 08 83 F? 18 72 EC }
		$h1 = { 00 6A 00 68 63 04 00 00 FF 35 [4] FF }

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and (((1 of ($h*)) and (4 of ($s*))) or (10 of them ))
}
