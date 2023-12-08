rule WEBSHELL_ASPX_ProxyShell_Exploitation_Aug21_1
{
	meta:
		description = "Detects unknown malicious loaders noticed in August 2021"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/VirITeXplorer/status/1430206853733097473"
		date = "2021-08-25"
		score = 90
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = ");eval/*asf" ascii

	condition:
		filesize <600KB and 1 of them
}
