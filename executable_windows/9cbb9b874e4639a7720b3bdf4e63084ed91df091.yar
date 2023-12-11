rule CN_Honker_Htran_V2_40_htran20
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file htran20.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b992bf5b04d362ed3757e90e57bc5d6b2a04e65c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s -slave  ConnectHost ConnectPort TransmitHost TransmitPort" fullword ascii
		$s2 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "%s -connect ConnectHost [ConnectPort]       Default:%d" fullword ascii
		$s5 = "[+] got, ip:%s, port:%d" fullword ascii
		$s6 = "[-] There is a error...Create a new connection." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
