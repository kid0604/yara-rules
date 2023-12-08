rule sig_2fb404bdcebc7acbeb598f8a2ddbecf48c60b113
{
	meta:
		description = "Auto-generated rule - file 2fb404bdcebc7acbeb598f8a2ddbecf48c60b113.codex"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-07-21"
		hash1 = "4f39d3e70ed1278d5fa83ed9f148ca92383ec662ac34635f7e56cc42eeaee948"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ":%:0:;:F:Q:\\:p:|:" fullword ascii
		$s2 = "6.666>6F6N6V6^6f6n6v6~6" fullword ascii
		$s3 = "6!6(6/666=6D6K6R6Y6r6:7" fullword ascii
		$s4 = "1t83jL.bjG" fullword ascii
		$s5 = "6!61666V6]6p6" fullword ascii
		$s6 = "2%2D2P2`2p2|2" fullword ascii
		$s7 = "42494@4G4N4U4\\4c4j4q4x4" fullword ascii
		$s8 = "9+92999@9G9N9U9\\9c9j9q9x9" fullword ascii
		$s9 = "4!4&43484E4J4W4\\4i4n4s4" fullword ascii
		$s10 = "5$5+52595@5G5N5U5\\5c5j5q5" fullword ascii
		$s11 = "1.252<2C2J2Q2X2_2f2m2t2{2" fullword ascii
		$s12 = "8 8%818:8?8K8Q8V8b8h8m8y8" fullword ascii
		$s13 = "9'93989=9B9K9P9U9Z9c9n9s9" fullword ascii
		$s14 = ":\":':,:8:=:B:R:Z:`:e:v:}:" fullword ascii
		$s15 = "=#=(=4=:=?=K=Q=V=b=k=p=|=" fullword ascii
		$s16 = "= =*=1=8=?=F=M=T=[=b=i=p=w=~=" fullword ascii
		$s17 = "3&3-343;3B3I3P3W3^3e3l3s3z3" fullword ascii
		$s18 = ":!:(:/:6:=:I:N:S:`:f:k:x:~:" fullword ascii
		$s19 = "cMDkAjy=" fullword ascii
		$s20 = "=#=/=4=9=E=J=O=[=`=e=q=v={=" fullword ascii
		$op0 = { e0 b3 42 00 c7 84 24 ac }
		$op1 = { 3c ee 42 00 c7 84 24 8c }
		$op2 = { a1 e0 79 44 00 83 c4 0c ff 74 24 1c ff 90 3c 01 }

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (10 of ($s*)) and 1 of ($op*)) or ( all of them )
}
