import "math"
import "pe"

rule FscanRule9
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "xyyyyzy" fullword ascii
		$s2 = ";<<<<=" fullword ascii
		$s3 = "uzesslkukey" fullword ascii
		$s4 = "NSpq.GSsql.DBv" fullword ascii
		$s5 = "* )N,,+8," fullword ascii
		$s6 = "* A1Q:" fullword ascii
		$s7 = "\"zftpgE;fkgc " fullword ascii
		$s8 = "wChCeye" fullword ascii
		$s9 = "41/2;-+-!4*" fullword ascii
		$s10 = "ANCELCIRCLE$Q" fullword ascii
		$s11 = "!%(+.~4!1" fullword ascii
		$s12 = "),.2-b0,/\"0" fullword ascii
		$s13 = "nAX* -" fullword ascii
		$s14 = "|FtprK!#pjHu" fullword ascii
		$s15 = "(,4 \"0 '$@" fullword ascii
		$s16 = "bsostsxs" fullword ascii
		$s17 = "qrsuxyy" fullword ascii
		$s18 = "rissedrub" fullword ascii
		$s19 = "nopquwz" fullword ascii
		$s20 = "zpcderiv" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and 4 of them
}
