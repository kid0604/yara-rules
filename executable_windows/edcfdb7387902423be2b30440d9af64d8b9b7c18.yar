import "pe"

rule MALWARE_Win_BackNet
{
	meta:
		author = "ditekSHen"
		description = "BackNet payload"
		clamav_sig = "MALWARE.Win.Trojan.BackNet"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Slave.Commands." fullword ascii
		$s2 = "StartKeylogger" fullword ascii
		$s3 = "StopKeylogger" fullword ascii
		$s4 = "KeyLoggerCommand" fullword ascii
		$s5 = "get_keyLoggerManager" fullword ascii
		$s6 = "get_IgnoreMutex" fullword ascii
		$s7 = "ListProcesses" fullword ascii
		$s8 = "downloadurl" fullword wide
		$pdb = "\\BackNet-master\\Slave\\obj\\Release\\Slave.pdb" ascii

	condition:
		uint16(0)==0x5a4d and ($pdb or all of ($s*))
}
