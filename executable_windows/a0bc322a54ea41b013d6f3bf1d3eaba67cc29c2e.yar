rule INDICATOR_TOOL_FScan
{
	meta:
		author = "ditekSHen"
		description = "Detects GoGo scan tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "fscan version:" ascii
		$s2 = "Citrix-ConfProxyCitrix-MetaframeCitrix-NetScalerCitrix-XenServerCitrix_Netscaler" ascii
		$s3 = "(AkamaiGHost)(DESCRIPTION=(Typecho</a>)(^.+)([0-9]+)(confluence.)(dotDefender)" ascii
		$s4 = "/fscan/" ascii
		$s5 = "WebScan.CheckDatas" ascii
		$s6 = "'Exploit.Test" ascii
		$s7 = "rules:" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
