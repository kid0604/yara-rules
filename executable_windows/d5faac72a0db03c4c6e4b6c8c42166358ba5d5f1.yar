rule d4fe01ea13cf9926c2cf51d0ffbd78f9a110f4b9
{
	meta:
		description = "Auto-generated rule - file d4fe01ea13cf9926c2cf51d0ffbd78f9a110f4b9.codex"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-07-21"
		hash1 = "d1dc9b2905264da34dc97d6c005810fbcc99be1a6b4b41f883bb179dbcacba6e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ":&:-:=:J:O:\\:m:r:" fullword ascii
		$s2 = "6)6/666;6N6W6^6c6t6y6" fullword ascii
		$s3 = "666Q6V6b6g6~6" fullword ascii
		$s4 = "0%0,010A0F0K0\\0a0f0w0|0" fullword ascii
		$s5 = "6!6(63686E6J6W6\\6i6n6{6" fullword ascii
		$s6 = "3 3%33383=3J3R3`3e3o3t3~3" fullword ascii
		$s7 = "4 4'40454:4G4M4R4_4e4j4w4" fullword ascii
		$s8 = "1#1(141=1B1N1T1Y1e1k1p1|1" fullword ascii
		$s9 = "?(?2?<?C?J?Q?X?_?f?m?t?{?" fullword ascii
		$s10 = "?#?*?1?8???F?M?T?[?b?i?p?w?" fullword ascii
		$s11 = "6)6/646@6F6K6W6]6b6n6w6|6" fullword ascii
		$s12 = "4#40454:4G4L4Q4^4c4h4u4z4" fullword ascii
		$s13 = "<\"<'<3<8<=<I<N<S<_<d<i<u<z<" fullword ascii
		$s14 = ">%>/>9>@>G>N>U>\\>c>j>q>" fullword ascii
		$s15 = "WTZDAE" fullword ascii
		$s16 = "060>0E0K0P0\\0b0g0v0|0" fullword ascii
		$s17 = "4#4-474A4K4U4\\4f4p4z4" fullword ascii
		$s18 = "7\"7,767@7J7T7^7h7q7{7" fullword ascii
		$s19 = ";\";';4;E;J;W;k;p;};" fullword ascii
		$s20 = ";0;;;F;Q;\\;g;r;};" fullword ascii
		$op0 = { a1 b8 63 44 00 83 c4 14 53 ff 75 14 56 57 ff 90 }
		$op1 = { 8b d8 8b 45 08 8b 40 3a 81 c3 00 10 00 00 03 c3 }
		$op2 = { 5c 2d 44 00 c7 84 24 c0 }

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (10 of ($s*)) and 1 of ($op*)) or ( all of them )
}
