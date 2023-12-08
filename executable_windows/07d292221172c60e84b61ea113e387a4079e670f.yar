rule HttpBrowser_RAT_Gen
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Generic"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 90
		hash1 = "0299493ccb175d452866f5e21d023d3e92cd8d28452517d1d19c0f05f2c5ca27"
		hash2 = "065d055a90da59b4bdc88b97e537d6489602cb5dc894c5c16aff94d05c09abc7"
		hash3 = "05c7291db880f94c675eea336ecd66338bd0b1d49ad239cc17f9df08106e6684"
		hash4 = "07133f291fe022cd14346cd1f0a649aa2704ec9ccadfab809ca9c48b91a7d81b"
		hash5 = "0f8893e87ddec3d98e39a57f7cd530c28e36d596ea0a1d9d1e993dc2cae0a64d"
		hash6 = "108e6633744da6efe773eb78bd0ac804920add81c3dde4b26e953056ac1b26c5"
		hash7 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
		hash8 = "1277ede988438d4168bb5b135135dd3b9ae7d9badcdf1421132ca4692dd18386"
		hash9 = "19be90c152f7a174835fd05a0b6f722e29c648969579ed7587ae036679e66a7b"
		hash10 = "1e7133bf5a9fe5e462321aafc2b7770b8e4183a66c7fef14364a0c3f698a29af"
		hash11 = "2264e5e8fcbdcb29027798b200939ecd8d1d3ad1ef0aef2b8ce7687103a3c113"
		hash12 = "2a1bdeb0a021fb0bdbb328bd4b65167d1f954c871fc33359cb5ea472bad6e13e"
		hash13 = "259a2e0508832d0cf3f4f5d9e9e1adde17102d2804541a9587a9a4b6f6f86669"
		hash14 = "240d9ce148091e72d8f501dbfbc7963997d5c2e881b4da59a62975ddcbb77ca2"
		hash15 = "211a1b195cf2cc70a2caf8f1aafb8426eb0e4bae955e85266490b12b5322aa16"
		hash16 = "2d25c6868c16085c77c58829d538b8f3dbec67485f79a059f24e0dce1e804438"
		hash17 = "2d932d764dd9b91166361d8c023d64a4480b5b587a6087b0ce3d2ac92ead8a7d"
		hash18 = "3556722d9aa37beadfa6ba248a66576f767e04b09b239d3fb0479fa93e0ba3fd"
		hash19 = "365e1d4180e93d7b87ba28ce4369312cbae191151ac23ff4a35f45440cb9be48"
		hash20 = "36c49f18ce3c205152eef82887eb3070e9b111d35a42b534b2fb2ee535b543c0"
		hash21 = "3eeb1fd1f0d8ab33f34183893c7346ddbbf3c19b94ba3602d377fa2e84aaad81"
		hash22 = "3fa8d13b337671323e7fe8b882763ec29b6786c528fa37da773d95a057a69d9a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" fullword wide
		$s1 = "HttpBrowser/1.0" fullword wide
		$s2 = "set cmd : %s" ascii fullword
		$s3 = "\\config.ini" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <45KB and filesize >20KB and all of them
}
