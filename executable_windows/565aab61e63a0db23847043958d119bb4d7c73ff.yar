rule EquationGroup_DUL
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file DUL"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "24d1d50960d4ebf348b48b4db4a15e50f328ab2c0e24db805b106d527fc5fe8e"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "?Usage: %s <shellcode> <output_file>" fullword ascii
		$x2 = "Here is the decoder+(encoded-decoder)+payload" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <80KB and 1 of them ) or ( all of them )
}
