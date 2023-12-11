rule EquationGroup_noclient_3_3_2
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "3cf0eb010c431372af5f32e2ee8c757831215f8836cabc7d805572bb5574fc72"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "127.0.0.1 is not advisable as a source. Use -l 127.0.0.1 to override this warning" fullword ascii
		$x2 = "iptables -%c OUTPUT -p tcp -d 127.0.0.1 --tcp-flags RST RST -j DROP;" fullword ascii
		$x3 = "noclient: failed to execute %s: %s" fullword ascii
		$x4 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
		$s5 = "Attempting connection from 0.0.0.0:" ascii

	condition:
		( filesize <1000KB and 1 of them )
}
