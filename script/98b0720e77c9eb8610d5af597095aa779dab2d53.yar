rule webshell_c99_locus7s_c99_w4cking_xxx
{
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "38fd7e45f9c11a37463c3ded1c76af4c"
		hash1 = "9c34adbc8fd8d908cbb341734830f971"
		hash2 = "ef43fef943e9df90ddb6257950b3538f"
		hash3 = "ae025c886fbe7f9ed159f49593674832"
		hash4 = "911195a9b7c010f61b66439d9048f400"
		hash5 = "697dae78c040150daff7db751fc0c03c"
		hash6 = "513b7be8bd0595c377283a7c87b44b2e"
		hash7 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash8 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash9 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash10 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash11 = "0d2c2c151ed839e6bafc7aa9c69be715"
		hash12 = "41af6fd253648885c7ad2ed524e0692d"
		hash13 = "6fcc283470465eed4870bcc3e2d7f14d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$res = @shell_exec($cfe);" fullword
		$s8 = "$res = @ob_get_contents();" fullword
		$s9 = "@exec($cfe,$res);" fullword

	condition:
		2 of them
}
