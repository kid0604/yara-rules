rule EXPL_Exchange_ProxyShell_Failed_Aug21_1 : SCRIPT
{
	meta:
		description = "Detects ProxyShell exploitation attempts in log files"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
		date = "2021-08-08"
		modified = "2021-08-09"
		os = "windows"
		filetype = "script"

	strings:
		$xr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|mapi\/nspi|EWS\/|X-Rps-CAT)[^\n]{1,400}401 0 0/ nocase ascii
		$xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}401 0 0/ nocase ascii

	condition:
		1 of them
}
