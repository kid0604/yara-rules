import "pe"

rule CobaltGang_Malware_Aug17_1
{
	meta:
		description = "Detects a Cobalt Gang malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://sslbl.abuse.ch/intel/6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
		date = "2017-08-09"
		hash1 = "6d70673b723f338b3febc9f1d69463bdd4775539cb92b5a5d8fccc0d977fa2f0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ServerSocket.EXE" fullword wide
		$s2 = "Incorrect version of WS2_32.dll found" fullword ascii
		$s3 = "Click 'Connect' to Connect to the Server.  'Disconnect' to disconnect from server." fullword wide
		$s4 = "Click 'Start' to start the Server.  'Stop' to Stop it." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 3 of them )
}
