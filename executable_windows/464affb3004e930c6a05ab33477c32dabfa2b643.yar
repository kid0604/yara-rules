import "pe"

rule OilRig_Malware_Nov17_13
{
	meta:
		description = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ClearskySec/status/933280188733018113"
		date = "2017-11-22"
		hash1 = "4f1e2df85c538875a7da877719555e21c33a558ac121eb715cf4e779d77ab445"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Release\\dnscat2.pdb" ascii
		$x2 = "cscript.exe //T:20 //Nologo " fullword ascii
		$a1 = "taskkill /F /IM cscript.exe" fullword ascii
		$a2 = "cmd.exe /c " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (pe.imphash()=="0160250adfc97f9d4a12dd067323ec61" or 1 of ($x*) or all of ($a*))
}
