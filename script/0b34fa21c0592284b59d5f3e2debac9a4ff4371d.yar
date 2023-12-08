rule EquationGroup_estesfox
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file estesfox"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "33530cae130ee9d9deeee60df9292c00242c0fe6f7b8eedef8ed09881b7e1d5a"
		os = "linux"
		filetype = "script"

	strings:
		$x1 = "chown root:root x;chmod 4777 x`' /tmp/logwatch.$2/cron" fullword ascii

	condition:
		all of them
}
