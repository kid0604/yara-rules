rule EquationGroup_morerats_client_noprep
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "a5b191a8ede8297c5bba790ef95201c516d64e2898efaeb44183f8fdfad578bb"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "storestr = 'echo -n \"%s\" | Store --nullterminate --file=\"%s\" --set=\"%s\"' % (nopenargs, outfile, VAR_NAME)" fullword ascii
		$x2 = "The NOPEN-args provided are injected into infile if it is a valid" fullword ascii
		$x3 = " -i                do not autokill after 5 hours" fullword ascii

	condition:
		( filesize <9KB and 1 of them )
}
