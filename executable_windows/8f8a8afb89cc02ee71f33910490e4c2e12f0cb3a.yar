rule Ransom_TeslaCrypt_2
{
	meta:
		description = "Detect the risk of Ransomware TeslaCrypt Rule 3"
		hash1 = "9b462800f1bef019d7ec00098682d3ea7fc60e6721555f616399228e4e3ad122"
		hash2 = "afaba2400552c7032a5c4c6e6151df374d0e98dc67204066281e30e6699dbd18"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
		$s2 = "SCwF- N" fullword ascii
		$s3 = "3!!!U[[[" fullword ascii
		$s4 = "  Unknown pseudo relocation protocol version %d." fullword ascii
		$s5 = "k3lYXY- " fullword ascii
		$s6 = "4#Z)* G" fullword ascii
		$s7 = "PAuA, K" fullword ascii
		$s8 = "ccJYo7V!" fullword ascii
		$s9 = "ZnXA85np" fullword ascii
		$s10 = "<\\t5</t1" fullword ascii
		$s11 = "mjvL<q&" fullword ascii
		$s12 = "jrotM=?f)" fullword ascii
		$s13 = "XVvbHC%" fullword ascii
		$s14 = "<EEFywww" fullword ascii
		$s15 = "Yywt)hK" fullword ascii
		$s16 = "UDzE/\"Q" fullword ascii
		$s17 = "mQaDQ5d]" fullword ascii
		$s18 = "OfSection" fullword wide
		$s19 = "ZwUnmapView" fullword wide
		$s20 = "  Unknown pseudo relocation bit size %d." fullword ascii
		$s21 = "11\\`@k#" fullword ascii
		$s22 = "V6Z<-1" fullword ascii
		$s23 = "Xb8em;" fullword ascii
		$s24 = "s l|k?" fullword ascii
		$s25 = "UVcSp$" fullword ascii
		$s26 = "6Y#^\":" fullword ascii
		$s27 = "2#Au$DRJ" fullword ascii
		$s28 = "QRPhd6D" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and (15 of them )) or ( all of them )
}
