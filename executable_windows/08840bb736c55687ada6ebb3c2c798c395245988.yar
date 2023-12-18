import "pe"

rule INDICATOR_TOOL_PROX_revsocks_alt_1
{
	meta:
		author = "ditekSHen"
		description = "Detects revsocks Reverse socks5 tunneler with SSL/TLS and proxy support"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "main.agentpassword" fullword ascii
		$s2 = "main.connectForSocks" fullword ascii
		$s3 = "main.connectviaproxy" fullword ascii
		$s4 = "main.DnsConnectSocks" fullword ascii
		$s5 = "main.listenForAgents" fullword ascii
		$s6 = "main.listenForClients" fullword ascii
		$s7 = "main.getPEMs" fullword ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and 4 of them
}
