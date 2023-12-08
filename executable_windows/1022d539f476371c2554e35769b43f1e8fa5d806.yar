rule INDICATOR_TOOL_SCN_SMBTouch
{
	meta:
		author = "ditekSHen"
		description = "Detects SMBTouch scanner EternalBlue, EternalChampion, EternalRomance, EternalSynergy"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[+] SMB Touch started" fullword ascii
		$s2 = "[-] Could not connect to share (0x%08X - %s)" fullword ascii
		$s3 = "[!] Target could be either SP%d or SP%d," fullword ascii
		$s4 = "[!] for these SMB exploits they are equivalent" fullword ascii
		$s5 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
		$s6 = "[+] Touch completed successfully" fullword ascii
		$s7 = "Network error while determining exploitability" fullword ascii
		$s8 = "Named pipe or share required for exploit" fullword ascii
		$w1 = "UsingNbt" fullword ascii
		$w2 = "TargetPort" fullword ascii
		$w3 = "TargetIp" fullword ascii
		$w4 = "RedirectedTargetPort" fullword ascii
		$w5 = "RedirectedTargetIp" fullword ascii
		$w6 = "NtlmHash" fullword ascii
		$w7 = "\\PIPE\\LANMAN" fullword ascii
		$w8 = "UserRejected: " fullword ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or all of ($w*))
}
