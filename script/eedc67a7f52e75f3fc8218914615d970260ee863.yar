rule Impacket_Lateral_Movement
{
	meta:
		description = "Detects Impacket Network Aktivity for Lateral Movement"
		author = "Markus Neis"
		reference = "https://github.com/CoreSecurity/impacket"
		date = "2018-03-22"
		score = 60
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "impacket.dcerpc.v5.transport(" ascii
		$s2 = "impacket.smbconnection(" ascii
		$s3 = "impacket.dcerpc.v5.ndr(" ascii
		$s4 = "impacket.spnego(" ascii
		$s5 = "impacket.smb(" ascii
		$s6 = "impacket.ntlm(" ascii
		$s7 = "impacket.nmb(" ascii

	condition:
		uint16(0)==0x5a4d and filesize <14000KB and 2 of them
}
