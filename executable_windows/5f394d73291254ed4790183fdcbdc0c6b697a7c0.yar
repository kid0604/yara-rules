import "math"
import "pe"

rule EarthWormRule3
{
	meta:
		description = "Detect the risk of Malware EarthWorm Rule 3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = " ./ew -s lcx_tran --listenport 1080 -connhost xxx.xxx.xxx.xxx --connport 8888" fullword ascii
		$s2 = " ./ew -s rssocks --refHost xxx.xxx.xxx.xxx --refPort 8888" fullword ascii
		$s3 = " -d refhost set the reflection host address." fullword ascii
		$s4 = " ./ew -s lcx_slave --refhost [ref_ip] --refport 1080 -connhost [connIP] --connport 8888" fullword ascii
		$s5 = " -f connhost set the connect host address ." fullword ascii
		$s6 = "<-- %3d --> (open)used/unused  %d/%d" fullword ascii
		$s7 = "lcx_tran 0.0.0.0:%d <--[%4d usec]--> %s:%d" fullword ascii
		$s8 = "Error : --> %d start server." fullword ascii
		$s9 = "ssocksd 0.0.0.0:%d <--[%4d usec]--> socks server" fullword ascii
		$s10 = "rcsocks 0.0.0.0:%d <--[%4d usec]--> 0.0.0.0:%d" fullword ascii
		$s11 = "Error : bind port %d ." fullword ascii
		$s12 = "--> %3d <-- (close)used/unused  %d/%d" fullword ascii
		$s13 = "Error on connect %s:%d [proto_init_cmd_rcsocket]" fullword ascii
		$s14 = " Tcp ---> %s:%d " fullword ascii
		$s15 = " ./ew -s lcx_listen --listenPort 1080 --refPort 8888" fullword ascii
		$s16 = " ./ew -s ssocksd --listenport 1080" fullword ascii
		$s17 = " -e refport set the reflection port." fullword ascii
		$s18 = " -g connport set the connect port." fullword ascii
		$s19 = "Error : Could not create socket [ port = %d ]." fullword ascii
		$s20 = " ./ew -s rcsocks --listenPort 1080 --refPort 8888" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 8 of them
}
