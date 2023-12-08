rule LOG_EXPL_SharePoint_CVE_2023_29357_Sep23_1
{
	meta:
		description = "Detects log entries that could indicate a successful exploitation of CVE-2023-29357 on Microsoft SharePoint servers with the published Python POC"
		author = "Florian Roth (with help from @LuemmelSec)"
		reference = "https://twitter.com/Gi7w0rm/status/1706764212704591953?s=20"
		date = "2023-09-28"
		modified = "2023-10-01"
		score = 70
		os = "windows,linux"
		filetype = "script"

	strings:
		$xr1 = /GET [a-z\.\/_]{0,40}\/web\/(siteusers|currentuser) - (80|443) .{10,200} (python-requests\/[0-9\.]{3,8}|-) [^ ]{1,160} [^4]0[0-9] /

	condition:
		$xr1
}
