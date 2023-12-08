rule Sphinx_Moth_h2t
{
	meta:
		description = "sphinx moth threat group file h2t.dat"
		author = "Kudelski Security - Nagravision SA (modified by Florian Roth)"
		reference = "www.kudelskisecurity.com"
		date = "2015-08-06"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%s <proxy ip> <proxy port> <target ip> <target port> <cmd> [arg1 cmd] ... [argX cmd]" fullword ascii
		$s1 = "[-] Error in connection() %d - %s" fullword ascii
		$s2 = "[-] Child process exit." fullword ascii
		$s3 = "POST http://%s:%s/ HTTP/1.1" fullword ascii
		$s4 = "pipe() to" fullword ascii
		$s5 = "pipe() from" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <156KB and ($x1 or all of ($s*))
}
