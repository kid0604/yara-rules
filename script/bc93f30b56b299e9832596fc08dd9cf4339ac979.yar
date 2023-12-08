rule redSails_PY
{
	meta:
		description = "Detects Red Sails Hacktool - Python"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/BeetleChunks/redsails"
		date = "2017-10-02"
		hash1 = "6ebedff41992b9536fe9b1b704a29c8c1d1550b00e14055e3c6376f75e462661"
		hash2 = "5ec20cb99030f48ba512cbc7998b943bebe49396b20cf578c26debbf14176e5e"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "Gained command shell on host" fullword ascii
		$x2 = "[!] Received an ERROR in shell()" fullword ascii
		$x3 = "Target IP address with backdoor installed" fullword ascii
		$x4 = "Open backdoor port on target machine" fullword ascii
		$x5 = "Backdoor port to open on victim machine" fullword ascii

	condition:
		1 of them
}
