rule Webshell_c99_4
{
	meta:
		description = "Detects C99 Webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
		hash3 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
		hash4 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
		hash5 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
		hash6 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash7 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
		hash8 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
		hash9 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash10 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
		hash11 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash12 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash13 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
		hash14 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "displaysecinfo(\"List of Attributes\",myshellexec(\"lsattr -a\"));" fullword ascii
		$s2 = "displaysecinfo(\"RAM\",myshellexec(\"free -m\"));" fullword ascii
		$s3 = "displaysecinfo(\"Where is perl?\",myshellexec(\"whereis perl\"));" fullword ascii
		$s4 = "$ret = myshellexec($handler);" fullword ascii
		$s5 = "if (posix_kill($pid,$sig)) {echo \"OK.\";}" fullword ascii

	condition:
		filesize <900KB and 1 of them
}
