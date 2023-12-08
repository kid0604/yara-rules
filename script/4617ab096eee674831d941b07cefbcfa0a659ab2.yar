rule EQGRP_ssh_telnet_29
{
	meta:
		description = "EQGRP Toolset Firewall - from files ssh.py, telnet.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "630d464b1d08c4dfd0bd50552bee2d6a591fb0b5597ecebaa556a3c3d4e0aa4e"
		hash2 = "07f4c60505f4d5fb5c4a76a8c899d9b63291444a3980d94c06e1d5889ae85482"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "received prompt, we're in" fullword ascii
		$s2 = "failed to login, bad creds, abort" fullword ascii
		$s3 = "sending command \" + str(n) + \"/\" + str(tot) + \", len \" + str(len(chunk) + " fullword ascii
		$s4 = "received nat - EPBA: ok, payload: mangled, did not run" fullword ascii
		$s5 = "no status returned from target, could be an exploit failure, or this is a version where we don't expect a stus return" ascii
		$s6 = "received arp - EPBA: ok, payload: fail" fullword ascii
		$s7 = "chopped = string.rstrip(payload, \"\\x0a\")" fullword ascii

	condition:
		( filesize <10KB and 2 of them ) or (3 of them )
}
