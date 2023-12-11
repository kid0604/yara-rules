import "pe"

rule MALWARE_Win_UNK04
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown malware (proxy tool)"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "127.0.0.1/%d" fullword ascii
		$x2 = "SYSTEM\\CurrentControlSet\\SERVICES\\PORTPROXY\\V4TOV4\\TCP" fullword ascii
		$x3 = "%s rundll32.exe" fullword ascii
		$s1 = "kxetray.exe" fullword ascii
		$s2 = "ksafe.exe" fullword ascii
		$s3 = "Mcshield.exe" fullword ascii
		$s4 = "Miner.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of ($x*) and 2 of ($s*)
}
