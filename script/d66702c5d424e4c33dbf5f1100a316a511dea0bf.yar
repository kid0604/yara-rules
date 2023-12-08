rule WEBSHELL_ASPX_ProxyShell_Aug21_2
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST), size and content"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
		date = "2021-08-13"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Page Language=" ascii nocase

	condition:
		uint32(0)==0x4e444221 and filesize <2MB and $s1
}
