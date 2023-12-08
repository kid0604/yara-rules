import "pe"

rule CN_disclosed_20180208_c
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyberintproject/status/961714165550342146"
		date = "2018-02-08"
		hash1 = "17475d25d40c877284e73890a9dd55fccedc6a5a071c351a8c342c8ef7f9cea7"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide
		$x2 = "schtasks /create /sc minute /mo 1 /tn Server /tr " fullword wide
		$x3 = "www.upload.ee/image/" wide
		$s1 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
		$s2 = "/Server.exe" fullword wide
		$s3 = "Executed As " fullword wide
		$s4 = "WmiPrvSE.exe" fullword wide
		$s5 = "Stub.exe" fullword ascii
		$s6 = "Download ERROR" fullword wide
		$s7 = "shutdown -r -t 00" fullword wide
		$s8 = "Select * From AntiVirusProduct" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 4 of them )
}
