import "pe"

rule Winnti_malware_FWPK
{
	meta:
		description = "Detects a Winnti malware - FWPKCLNT.SYS"
		author = "Florian Roth (Nextron Systems)"
		reference = "VTI research"
		date = "2015-10-10"
		modified = "2023-01-06"
		score = 75
		hash1 = "1098518786c84b0d31f215122275582bdcd1666653ebc25d50a142b4f5dabf2c"
		hash2 = "9a684ffad0e1c6a22db1bef2399f839d8eff53d7024fb014b9a5f714d11febd7"
		hash3 = "a836397817071c35e24e94b2be3c2fa4ffa2eb1675d3db3b4456122ff4a71368"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" wide
		$s1 = "%x:%d->%x:%d, Flag %s%s%s%s%s, seq %u, ackseq %u, datalen %u" fullword ascii
		$s2 = "FWPKCLNT.SYS" fullword ascii
		$s3 = "Port Layer" fullword wide
		$s4 = "%x->%x, icmp type %d, code %d" fullword ascii
		$s5 = "\\BaseNamedObjects\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28E}" wide
		$s6 = "\\Ndi\\Interfaces" wide
		$s7 = "\\Device\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" wide
		$s8 = "Bad packet" fullword ascii
		$s9 = "\\BaseNamedObjects\\EKV0000000000" wide
		$s10 = "%x->%x" fullword ascii
		$s11 = "IPInjectPkt" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <642KB and all of them
}
