rule WEBSHELL_ASPX_ProxyShell_Sep21_1
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and base64 decoded request"
		author = "Tobias Michalski"
		date = "2021-09-17"
		reference = "Internal Research"
		hash = "219468c10d2b9d61a8ae70dc8b6d2824ca8fbe4e53bbd925eeca270fef0fd640"
		score = 75
		os = "windows"
		filetype = "script"

	strings:
		$s = ".FromBase64String(Request["

	condition:
		uint32(0)==0x4e444221 and any of them
}
