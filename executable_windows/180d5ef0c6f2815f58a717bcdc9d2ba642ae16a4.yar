import "pe"

rule BronzeButler_xxmm_1
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		date = "2017-10-14"
		hash1 = "7197de18bc5a4c854334ff979f3e4dafa16f43d7bf91edfe46f03e6cc88f7b73"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Release\\ReflectivLoader.pdb" ascii
		$x3 = "\\Projects\\xxmm2\\Release\\" ascii
		$x5 = "http://127.0.0.1/phptunnel.php" fullword ascii
		$s1 = "xxmm2.exe" fullword ascii
		$s2 = "\\AvUpdate.exe" wide
		$s3 = "stdapi_fs_file_download" fullword ascii
		$s4 = "stdapi_syncshell_open" fullword ascii
		$s5 = "stdapi_execute_sleep" fullword ascii
		$s6 = "stdapi_syncshell_kill" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (1 of ($x*) or 4 of them )
}
