import "pe"

rule Slingshot_APT_Malware_1
{
	meta:
		description = "Detects malware from Slingshot APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/apt-slingshot/84312/"
		date = "2018-03-09"
		hash1 = "4b250304e28648574b441831bf579b844e8e1fda941fb7f86a7ea7c4291bbca6"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SlingDll.dll" fullword ascii
		$s2 = "BogusDll." ascii
		$s3 = "smsvcrt -h 0x%p" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (pe.imphash()=="7ead4bb0d752003ce7c062adb7ffc51a" or pe.exports("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW0000") or 1 of them )
}
