rule EquationGroup_morerats_client_addkey
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "6c67c03716d06a99f20c1044585d6bde7df43fee89f38915db0b03a42a3a9f4b"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "print '  -s storebin  use storebin as the Store executable\\n'" fullword ascii
		$x2 = "os.system('%s --file=\"%s\" --wipe > /dev/null' % (storebin, b))" fullword ascii
		$x3 = "print '  -k keyfile   the key text file to inject'" fullword ascii

	condition:
		( filesize <20KB and 1 of them )
}
