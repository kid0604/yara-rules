rule network_dyndns
{
	meta:
		author = "x0r"
		description = "Communications dyndns network"
		version = "0.1"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = ".no-ip.org"
		$s2 = ".publicvm.com"
		$s3 = ".linkpc.net"
		$s4 = ".dynu.com"
		$s5 = ".dynu.net"
		$s6 = ".afraid.org"
		$s7 = ".chickenkiller.com"
		$s8 = ".crabdance.com"
		$s9 = ".ignorelist.com"
		$s10 = ".jumpingcrab.com"
		$s11 = ".moo.com"
		$s12 = ".strangled.com"
		$s13 = ".twillightparadox.com"
		$s14 = ".us.to"
		$s15 = ".strangled.net"
		$s16 = ".info.tm"
		$s17 = ".homenet.org"
		$s18 = ".biz.tm"
		$s19 = ".continent.kz"
		$s20 = ".ax.lt"
		$s21 = ".system-ns.com"
		$s22 = ".adultdns.com"
		$s23 = ".craftx.biz"
		$s24 = ".ddns01.com"
		$s25 = ".dns53.biz"
		$s26 = ".dnsapi.info"
		$s27 = ".dnsd.info"
		$s28 = ".dnsdynamic.com"
		$s29 = ".dnsdynamic.net"
		$s30 = ".dnsget.org"
		$s31 = ".fe100.net"
		$s32 = ".flashserv.net"
		$s33 = ".ftp21.net"

	condition:
		any of them
}
