rule APT_NK_Lazarus_Network_Backdoor_Unpacked
{
	meta:
		author = "f-secure"
		description = "Detects unpacked variant of Lazarus Group network backdoor"
		date = "2020-06-10"
		reference = "https://labs.f-secure.com/publications/ti-report-lazarus-group-cryptocurrency-vertical"
		os = "windows"
		filetype = "executable"

	strings:
		$str_netsh_1 = "netsh firewall add portopening TCP %d" ascii wide nocase
		$str_netsh_2 = "netsh firewall delete portopening TCP %d" ascii wide nocase
		$str_mask_1 = "cmd.exe /c \"%s >> %s 2>&1\"" ascii wide
		$str_mask_2 = "cmd.exe /c \"%s 2>> %s\"" ascii wide
		$str_mask_3 = "%s\\%s\\%s" ascii wide
		$str_other_1 = "perflog.dat" ascii wide nocase
		$str_other_2 = "perflog.evt" ascii wide nocase
		$str_other_3 = "cbstc.log" ascii wide nocase
		$str_other_4 = "LdrGetProcedureAddress" ascii
		$str_other_5 = "NtProtectVirtualMemory" ascii

	condition:
		int16 (0)==0x5a4d and filesize <3000KB and 1 of ($str_netsh*) and 1 of ($str_mask*) and 1 of ($str_other*)
}
