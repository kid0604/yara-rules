rule hacktool_macos_exploit_tpwn
{
	meta:
		description = "tpwn exploits a null pointer dereference in XNU to escalate privileges to root."
		reference = "https://www.rapid7.com/db/modules/exploit/osx/local/tpwn"
		author = "@mimeframe"
		os = "macos"
		filetype = "executable"

	strings:
		$a1 = "[-] Couldn't find a ROP gadget, aborting." wide ascii
		$a2 = "leaked kaslr slide," wide ascii
		$a3 = "didn't get root, but this system is vulnerable." wide ascii
		$a4 = "Escalating privileges! -qwertyoruiop" wide ascii

	condition:
		2 of ($a*)
}
