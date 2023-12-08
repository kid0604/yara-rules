rule apt_win_exe_trojan_derusbi_alt_1
{
	meta:
		description = "Detects Derusbi Backdoor Win32"
		author = "Fidelis Cybersecurity"
		date = "2016/02/29"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		os = "windows"
		filetype = "executable"

	strings:
		$sa_4 = "HOST: %s:%d"
		$sa_6 = "User-Agent: Mozilla"
		$sa_7 = "Proxy-Connection: Keep-Alive"
		$sa_8 = "Connection: Keep-Alive"
		$sa_9 = "Server: Apache"
		$sa_12 = "ZwUnloadDriver"
		$sa_13 = "ZwLoadDriver"
		$sa_18 = "_time64"
		$sa_19 = "DllRegisterServer"
		$sa_20 = "DllUnregisterServer"
		$sa_21 = { 8b [5] 8b ?? d3 ?? 83 ?? 08 30 [5] 40 3b [5] 72 }
		$sb_1 = "PCC_CMD_PACKET"
		$sb_2 = "PCC_CMD"
		$sb_3 = "PCC_BASEMOD"
		$sb_4 = "PCC_PROXY"
		$sb_5 = "PCC_SYS"
		$sb_6 = "PCC_PROCESS"
		$sb_7 = "PCC_FILE"
		$sb_8 = "PCC_SOCK"
		$sc_1 = "bcdedit -set testsigning" wide ascii
		$sc_2 = "update.microsoft.com" wide ascii
		$sc_3 = "_crt_debugger_hook" wide ascii
		$sc_4 = "ue8G5" wide ascii
		$sd_2 = "\\\\.\\pipe\\%s" wide ascii
		$sd_3 = ".dat" wide ascii
		$sd_4 = "CONNECT %s:%d" wide ascii
		$sd_5 = "\\Device\\" wide ascii
		$se_1 = "-%s-%04d" wide ascii
		$se_2 = "-%04d" wide ascii
		$se_5 = "2.03" wide ascii

	condition:
		uint16(0)==0x5A4D and ( all of ($sa_*) or ((8 of ($sa_*)) and ((5 of ($sb_*)) or (3 of ($sc_*)) or ( all of ($sd_*)) or (1 of ($sc_*) and all of ($se_*)))))
}
