rule possible_includes_base64_packed_functions
{
	meta:
		impact = 5
		hide = true
		desc = "Detects possible includes and packed functions"
		description = "Detects possible includes and packed functions"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$f = /(atob|btoa|;base64|base64,)/ nocase
		$fff = /([A-Za-z0-9]{4})*([A-Za-z0-9]{2}==|[A-Za-z0-9]{3}=|[A-Za-z0-9]{4})/

	condition:
		$f and $fff
}
