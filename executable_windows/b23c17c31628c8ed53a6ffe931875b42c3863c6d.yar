import "pe"

rule BlackShades_25052015
{
	meta:
		author = "Brian Wallace (@botnet_hunter)"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/PoisonIvy"
		ref = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
		family = "blackshades"
		description = "Detects BlackShades malware family"
		os = "windows"
		filetype = "executable"

	strings:
		$string1 = "bss_server"
		$string2 = "txtChat"
		$string3 = "UDPFlood"

	condition:
		all of them
}
