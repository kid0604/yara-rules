rule WebShell_cgi
{
	meta:
		description = "Semi-Auto-generated  - file WebShell.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "bc486c2e00b5fc3e4e783557a2441e6f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "WebShell.cgi"
		$s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else"

	condition:
		all of them
}
