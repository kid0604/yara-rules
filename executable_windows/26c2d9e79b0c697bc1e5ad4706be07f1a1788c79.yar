import "pe"

rule MALWARE_Win_AsyncRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects AsyncRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "AsyncRAT" fullword ascii
		$x2 = "AsyncRAT 0." wide
		$x3 = /AsyncRAT\s[0-9]\.[0-9]\.[0-9][A-Z]/ fullword wide
		$s1 = "/create /sc onlogon /rl highest /tn" fullword wide
		$s2 = "/C choice /C Y /N /D Y /T 1 & Del \"" fullword wide
		$s3 = "{{ ProcessId = {0}, Name = {1}, ExecutablePath = {2} }}" fullword wide
		$s4 = "Stub.exe" fullword ascii wide
		$s5 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\UCKH" ascii wide
		$s6 = "VirtualBox" fullword ascii wide
		$s7 = "/target:winexe /platform:x86 /optimize+" fullword ascii wide
		$s8 = "Win32_ComputerSystem" ascii wide
		$s9 = "Win32_Process Where ParentProcessID=" ascii wide
		$s10 = "etirWgeR.llehShsW" ascii wide
		$s11 = "usbSpread" fullword ascii wide
		$cnc1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" fullword ascii wide
		$cnc2 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1" fullword ascii wide
		$cnc3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii wide
		$cnc4 = "POST / HTTP/1.1" fullword ascii wide

	condition:
		(( uint16(0)==0x5a4d and filesize <4000KB) and (1 of ($x*) or 6 of ($s*) or all of ($cnc*) or (4 of ($s*) and 2 of ($cnc*)))) or (1 of ($x*) or 6 of ($s*) or all of ($cnc*) or (4 of ($s*) and 2 of ($cnc*)))
}
