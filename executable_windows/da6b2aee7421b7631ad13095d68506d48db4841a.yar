import "math"
import "pe"

rule FscanRule8
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SZTZVZWZL" fullword ascii
		$s2 = "XjEkfCxOE" fullword ascii
		$s3 = "zODQxNDMxMjQz" fullword ascii
		$s4 = "gethped" fullword ascii
		$s5 = "templa" fullword ascii
		$s6 = "prfaildmu" fullword ascii
		$s7 = ".dllgq" fullword ascii
		$s8 = "miNm.mmo" fullword ascii
		$s9 = "dVyy:\\3" fullword ascii
		$s10 = "\\4567\\." fullword ascii
		$s11 = "FanX.PQX" fullword ascii
		$s12 = "NTLMSSPH" fullword ascii
		$s13 = "WSAGetOv" fullword ascii
		$s14 = "*6:\"*\"F" fullword ascii
		$s15 = "<2E2f@&`," fullword ascii
		$s16 = "?2.16.840" fullword ascii
		$s17 = "* B+xz" fullword ascii
		$s18 = "~ ~'~(~,~-~/~3~6~" fullword ascii
		$s19 = "4`6`7`8`$  " fullword ascii
		$s20 = "\";476837" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and 3 of them
}
