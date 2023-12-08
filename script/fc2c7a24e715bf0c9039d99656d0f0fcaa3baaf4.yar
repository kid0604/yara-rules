rule Invoke_SMBExec
{
	meta:
		description = "Detects Invoke-WmiExec or Invoke-SmbExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		date = "2017-06-14"
		hash1 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Invoke-SMBExec -Target" fullword ascii
		$x2 = "$packet_SMB_header = Get-PacketSMBHeader 0x71 0x18 0x07,0xc8 $SMB_tree_ID $process_ID_bytes $SMB_user_ID" fullword ascii
		$s1 = "Write-Output \"Command executed with service $SMB_service on $Target\"" fullword ascii
		$s2 = "$packet_RPC_data = Get-PacketRPCBind 1 0xb8,0x10 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x02,0x00" fullword ascii
		$s3 = "$SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \\svcctl" fullword ascii

	condition:
		( filesize <400KB and 1 of them )
}
