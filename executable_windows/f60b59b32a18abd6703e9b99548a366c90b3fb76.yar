import "pe"

rule MALWARE_Win_EXEPWSH_DLAgent
{
	meta:
		author = "ditekSHen"
		description = "Detects SystemBC"
		os = "windows"
		filetype = "executable"

	strings:
		$pwsh = "powershell" fullword ascii
		$bitstansfer = "Start-BitsTransfer" ascii wide
		$s1 = "GET %s HTTP/1" ascii
		$s2 = "User-Agent:" ascii
		$s3 = "-WindowStyle Hidden -ep bypass -file \"" fullword ascii
		$s4 = "LdrLoadDll" fullword ascii
		$v1 = "BEGINDATA" fullword ascii
		$v2 = /HOST\d:/ ascii
		$v3 = /PORT\d:/ ascii
		$v4 = "TOR:" fullword ascii
		$v5 = "Fwow64" fullword ascii
		$v6 = "start" fullword ascii

	condition:
		uint16(0)==0x5a4d and (($pwsh and ($bitstansfer or 2 of ($s*))) or (5 of ($v*)))
}
