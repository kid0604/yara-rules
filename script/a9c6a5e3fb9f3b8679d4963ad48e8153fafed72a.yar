rule LOG_APT_WEBSHELL_Solarwinds_SUNBURST_Report_Webshell_Dec20_2
{
	meta:
		description = "Detects webshell access mentioned in FireEye's SUNBURST report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/"
		date = "2020-12-21"
		os = "windows,linux"
		filetype = "script"

	strings:
		$xr1 = /logoimagehandler.ashx[^\n\s]{1,400}clazz=/ ascii wide

	condition:
		$xr1
}
