import "pe"

rule Monsoon_APT_Malware_1
{
	meta:
		description = "Detects malware from Monsoon APT"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.fortinet.com/2017/04/05/in-depth-look-at-new-variant-of-monsoon-apt-backdoor-part-2"
		date = "2017-09-08"
		modified = "2023-01-06"
		hash1 = "c9642f44d33e4c990066ce6fa0b0956ff5ace6534b64160004df31b9b690c9cd"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd.exe /c start " fullword ascii
		$s2 = "\\Microsoft\\Templates\\" ascii
		$s3 = "\\Microsoft\\Windows\\" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="a0c824244f1d36ea1dd2759cf7599cd1" or all of them ))
}
