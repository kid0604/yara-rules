rule sig_7acb8d6d4c062c3097a7d31df103bc4d018519f9
{
	meta:
		description = "Auto-generated rule - file 7acb8d6d4c062c3097a7d31df103bc4d018519f9.codex"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-07-21"
		hash1 = "e1607486cbb2d111d5df314fe58948aa0dc5897f56f7fd763c62bb30651380e3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "5(666Z6c6" fullword ascii
		$s2 = "Wlm;y%UD%d" fullword ascii
		$s3 = ";1;9;@;G;N;U;\\;c;j;q;x;" fullword ascii
		$s4 = "8 8'8.858<8C8J8Q8X8_8f8m8t8" fullword ascii
		$s5 = "2 2,282=2B2G2P2U2Z2_2h2s2x2" fullword ascii
		$s6 = "4'5.555<5C5J5Q5X5_5f5m5t5{5" fullword ascii
		$s7 = "0#0*01080?0F0M0T0[0b0i0p0w0" fullword ascii
		$s8 = "6$6,616=6B6G6S6X6]6i6n6s6" fullword ascii
		$s9 = "=\"=)=0=7=>=E=L=S=Z=a=h=" fullword ascii
		$s10 = "6&6-646;6B6I6P6W6^6e6l6s6z6" fullword ascii
		$s11 = "O.QrH@" fullword ascii
		$s12 = ">\">/>4>A>F>S>X>e>j>w>|>" fullword ascii
		$s13 = "0#0(040=0B0N0T0Y0e0k0p0|0" fullword ascii
		$s14 = "5)5/545@5F5K5W5`5e5q5w5|5" fullword ascii
		$s15 = "=!=&=3=8=E=N=S=`=e=s=x=}=" fullword ascii
		$s16 = ":(:/:6:=:D:K:R:Y:`:g:n:u:|:" fullword ascii
		$s17 = "7\"727<7F7M7W7a7k7u7" fullword ascii
		$s18 = "2+21262E2K2P2\\2h2m2|2" fullword ascii
		$s19 = ";/;5;:;G;V;\\;a;n;};" fullword ascii
		$s20 = ";\";-;8;C;N;^;i;t;" fullword ascii
		$op0 = { ff 44 24 14 8d 47 44 50 a1 08 63 44 00 ff 90 84 }
		$op1 = { 6d 43 00 c7 84 24 10 03 00 00 0c 6d 43 00 c7 84 }
		$op2 = { c7 43 0c 20 02 00 00 89 5d f0 ff 90 f8 }

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (10 of ($s*)) and 1 of ($op*)) or ( all of them )
}
