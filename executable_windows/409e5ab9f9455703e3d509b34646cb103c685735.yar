rule sig_5783b35b2eace55a5762df27fcb0b0fb28371b3e
{
	meta:
		description = "Auto-generated rule - file 5783b35b2eace55a5762df27fcb0b0fb28371b3e.codex"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-07-21"
		hash1 = "72513534f2e0f3e77a22023b887df3718c9df70686eb0ae58cbbde2f90f447e4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "B+P:\\6" fullword ascii
		$s2 = "6.666K6S6d6l6}6" fullword ascii
		$s3 = "0!0&0+0<0A0F0W0\\0a0n0z0" fullword ascii
		$s4 = ";#;);.;:;@;E;Q;W;\\;h;q;v;" fullword ascii
		$s5 = "2#2-222F2L2W2\\2b2g2x2~2" fullword ascii
		$s6 = "9\"9)90979>9E9L9S9Z9k9}9" fullword ascii
		$s7 = "6-747;7B7I7P7W7^7e7l7s7z7" fullword ascii
		$s8 = "4\"4'43494>4J4P4U4a4g4l4x4" fullword ascii
		$s9 = ":#:(:4:::?:K:T:Y:e:k:p:|:" fullword ascii
		$s10 = "WD.hyA" fullword ascii
		$s11 = "<\"<)<0<7<><E<L<S<Z<a<h<" fullword ascii
		$s12 = "=&=,=1=>=D=I=V=_=d=q=w=|=" fullword ascii
		$s13 = "; ;(;0;8;@;H;P;X;`;h;p;{;" fullword ascii
		$s14 = "<\"<)<0<7<><E<L<S<Z<a<h<o<v<" fullword ascii
		$s15 = "6#6(616;6@6I6S6X6d6n6s6|6" fullword ascii
		$s16 = "(%r-c;u" fullword ascii
		$s17 = "3%3G3N3U3\\3c3j3q3x3" fullword ascii
		$s18 = "7\"767T7[7b7i7p7w7~7" fullword ascii
		$s19 = "1 1-1>1C1P1a1f1s1" fullword ascii
		$s20 = "8 8&8,8A8M8^8d8i8" fullword ascii
		$op0 = { e0 b3 42 00 c7 84 24 ac }
		$op1 = { a1 e0 79 44 00 57 ff 75 1c ff 90 78 01 00 00 83 }
		$op2 = { 3c ee 42 00 c7 84 24 8c }

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (10 of ($s*)) and 1 of ($op*)) or ( all of them )
}
