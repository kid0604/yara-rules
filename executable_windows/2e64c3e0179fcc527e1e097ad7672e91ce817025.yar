import "pe"

rule clean_apt15_patchedcmd_alt_1
{
	meta:
		author = "Ahmed Zaki"
		description = "This is a patched CMD. This is the CMD that RoyalCli uses."
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "eisableCMD" wide
		$ = "%WINDOWS_COPYRIGHT%" wide
		$ = "Cmd.Exe" wide
		$ = "Windows Command Processor" wide

	condition:
		all of them
}
