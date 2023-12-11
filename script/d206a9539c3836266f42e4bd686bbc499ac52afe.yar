rule EquationGroup_elatedmonkey_1_0_1_1
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file elatedmonkey.1.0.1.1.sh"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "bf7a9dce326604f0681ca9f7f1c24524543b5be8b6fcc1ba427b18e2a4ff9090"
		os = "linux"
		filetype = "script"

	strings:
		$x3 = "Usage: $0 ( -s IP PORT | CMD )" fullword ascii
		$s5 = "os.execl(\"/bin/sh\", \"/bin/sh\", \"-c\", \"$CMD\")" fullword ascii
		$s13 = "PHP_SCRIPT=\"$HOME/public_html/info$X.php\"" fullword ascii
		$s15 = "cat > /dev/tcp/127.0.0.1/80 <<END" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <5KB and (1 of ($x*) and 5 of ($s*))) or ( all of them )
}
