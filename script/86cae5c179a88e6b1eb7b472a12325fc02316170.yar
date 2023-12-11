rule EquationGroup_magicjack_v1_1_0_0_client_1_1_0_0
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file magicjack_v1.1.0.0_client-1.1.0.0.py"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "result = self.send_command(\"ls -al %s\" % self.options.DIR)" fullword ascii
		$x2 = "cmd += \"D=-l%s \" % self.options.LISTEN_PORT" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <80KB and 1 of them )
}
