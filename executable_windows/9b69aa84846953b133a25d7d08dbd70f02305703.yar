import "pe"

rule clean_apt15_patchedcmd
{
	meta:
		author = "Ahmed Zaki"
		description = "This is a patched CMD. This is the CMD that RoyalCli uses."
		sha256 = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "eisableCMD" wide
		$ = "%WINDOWS_COPYRIGHT%" wide
		$ = "Cmd.Exe" wide
		$ = "Windows Command Processor" wide

	condition:
		uint16(0)==0x5A4D and all of them
}
