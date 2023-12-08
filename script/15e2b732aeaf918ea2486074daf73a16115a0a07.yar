rule webshell_000_403_c5_config_myxx_queryDong_spyjsp2010_zend
{
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash4 = "e0354099bee243702eb11df8d0e046df"
		hash5 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash6 = "655722eaa6c646437c8ae93daac46ae0"
		hash7 = "591ca89a25f06cf01e4345f98a22845c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "return new Double(format.format(value)).doubleValue();" fullword
		$s5 = "File tempF = new File(savePath);" fullword
		$s9 = "if (tempF.isDirectory()) {" fullword

	condition:
		2 of them
}
