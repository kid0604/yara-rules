rule EquationGroup_elatedmonkey_1_0_1_1_alt_1
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file elatedmonkey.1.0.1.1.sh"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		modified = "2022-08-18"
		hash1 = "bf7a9dce326604f0681ca9f7f1c24524543b5be8b6fcc1ba427b18e2a4ff9090"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "Usage: $0 ( -s IP PORT | CMD )" fullword ascii
		$s2 = "os.execl(\"/bin/sh\", \"/bin/sh\", \"-c\", \"$CMD\")" fullword ascii
		$s3 = "PHP_SCRIPT=\"$HOME/public_html/info$X.php\"" fullword ascii
		$s4 = "cat > /dev/tcp/127.0.0.1/80 <<" ascii

	condition:
		filesize <15KB and 2 of them
}
