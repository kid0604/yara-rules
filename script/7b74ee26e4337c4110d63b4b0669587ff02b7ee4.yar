import "pe"

rule Invoke_WMIExec_11462
{
	meta:
		description = "file Invoke-WMIExec.ps1"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2022-05-01"
		hash1 = "c4939f6ad41d4f83b427db797aaca106b865b6356b1db3b7c63b995085457222"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command \"comman" ascii
		$x2 = "Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command \"comman" ascii
		$x3 = "Write-Output \"[+] Command executed with process ID $target_process_ID on $target_long\"" fullword ascii
		$x4 = "Invoke-WMIExec -Target 192.168.100.20 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0" fullword ascii
		$s5 = "$target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList" fullword ascii
		$s6 = "$WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostna" ascii
		$s7 = "Execute a command." fullword ascii
		$s8 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessReques" fullword ascii
		$s9 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader" fullword ascii
		$s10 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader\"" fullword ascii
		$s11 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader\"," ascii
		$s12 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFl" ascii
		$s13 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader\",[" ascii
		$s14 = "$target_process_ID = Get-UInt16DataLength 1141 $WMI_client_receive" fullword ascii
		$s15 = "$hostname_length = [System.BitConverter]::GetBytes($auth_hostname.Length + 1)" fullword ascii
		$s16 = "Write-Verbose \"[*] Attempting command execution\"" fullword ascii
		$s17 = "$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id" fullword ascii
		$s18 = "$auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_host" fullword ascii
		$s19 = "$auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostna" fullword ascii
		$s20 = "[Byte[]]$packet_private_header = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 40) + 0x00,0x00,0x00,0x00" fullword ascii

	condition:
		uint16(0)==0x7566 and filesize <300KB and 1 of ($x*) and 4 of them
}
