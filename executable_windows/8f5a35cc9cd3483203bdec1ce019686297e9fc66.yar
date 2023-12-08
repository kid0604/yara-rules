import "math"
import "pe"

rule FscanRule12
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 12"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mTmVmWmZm" fullword ascii
		$s2 = "templa" fullword ascii
		$s3 = "yOip 2%S%oli" fullword ascii
		$s4 = "\\5667\\." fullword ascii
		$s5 = " (/7=E44." fullword ascii
		$s6 = "~ ~'~(~,~-~/~3~6~" fullword ascii
		$s7 = "lspyc.y" fullword ascii
		$s8 = "* V-X<K" fullword ascii
		$s9 = " $}3-4-3+e" fullword ascii
		$s10 = "6F%}^6e\"" fullword ascii
		$s11 = "2!0-3&023" fullword ascii
		$s12 = "WSAGetOvY" fullword ascii
		$s13 = "(BP - " fullword ascii
		$s14 = "nIRC2n%+I" fullword ascii
		$s15 = " 2!2\"2#2$2%2&2'2" fullword ascii
		$s16 = "kernel32Il" fullword ascii
		$s17 = "_\")2^2({" fullword ascii
		$s18 = "41/2;-+-!4*" fullword ascii
		$s19 = "[/\\2222]^_`(" fullword ascii
		$s20 = ".IJm2g vZhIrCH" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and 7 of them
}
